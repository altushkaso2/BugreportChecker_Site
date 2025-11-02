#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        LogKeywordRule::LogKeywordRule() : threat_lexicon({
            {"com.google.android.gms.unstable", "GMS Unstable package", 1, DetectionCategory::RootHidingAndEvasion},
            {"org.microg.gms.core", "MicroG services", 2, DetectionCategory::RootHidingAndEvasion},
            {"/lspd/service.jar", "LSPosed Zygote injection", 5, DetectionCategory::RootAndFrameworks},
            {"post-fs-data.d", "Magisk boot script execution", 4, DetectionCategory::RootAndFrameworks}
        }) {}

        std::vector<std::string> LogKeywordRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG", "LAST KMSG"}; }
        DetectionCategory LogKeywordRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void LogKeywordRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            for (const auto& [keyword, name, score, category] : threat_lexicon) {
                if (line.find(keyword) != std::string_view::npos) {
                    if (context.reported_log_threats.find(name) == context.reported_log_threats.end()) {
                        std::string report_str = name + " detected in log: " + std::string(line);
                        report.detections[category].insert(report_str);
                        report.totalScore += score;
                        context.reported_log_threats.insert(name);
                    }
                }
            }
        }
        
        int LogKeywordRule::getScore(const std::string&) const { return 0; }

        std::vector<std::string> InvalidSelinuxTransitionRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG"}; }
        DetectionCategory InvalidSelinuxTransitionRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void InvalidSelinuxTransitionRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if(line.find("scontext=u:r:untrusted_app") != std::string_view::npos && line.find("tcontext=u:r:magisk:s0") != std::string_view::npos) {
                std::string report_str = "SELinux Anomaly: App requested root via Magisk context.";
                if (report.detections[DetectionCategory::AnomalousLogs].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int InvalidSelinuxTransitionRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("requested root via Magisk context") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> SelinuxNeverallowRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG", "EVENT LOG"}; }
        DetectionCategory SelinuxNeverallowRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void SelinuxNeverallowRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("avc: denied") != std::string_view::npos && line.find("neverallow") != std::string_view::npos) {
                std::string report_str = "CRITICAL: SELinux 'neverallow' rule violation detected.";
                if (report.detections[DetectionCategory::AnomalousLogs].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int SelinuxNeverallowRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("neverallow") != std::string::npos) return 7;
            return 0;
        }

        std::vector<std::string> SelinuxDenialSpamRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG", "EVENT LOG"}; }
        DetectionCategory SelinuxDenialSpamRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void SelinuxDenialSpamRule::processLine(std::string_view line, ReportData&, AnalysisContext& context) {
            if (line.find("avc: denied") != std::string_view::npos) {
                context.selinux_denial_count++;
            }
        }
        
        void SelinuxDenialSpamRule::finalize(ReportData& report, AnalysisContext& context) {
            if (context.selinux_denial_count > SPAM_THRESHOLD) {
                std::string report_str = "SELinux Anomaly: " + std::to_string(context.selinux_denial_count) + " denials detected, indicating aggressive system probing.";
                if (report.detections[DetectionCategory::AnomalousLogs].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int SelinuxDenialSpamRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("aggressive system probing") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> SELinuxStateRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG", "SYSTEM PROPERTIES"}; }
        DetectionCategory SELinuxStateRule::getTargetCategory() const { return DetectionCategory::SuspiciousProperties; }

        void SELinuxStateRule::processLine(std::string_view line, ReportData&, AnalysisContext& context) {
            if (context.seLinuxState == AnalysisContext::SELinuxState::Permissive) return;

            if (line.rfind("Command line:", 0) == 0 || line.rfind("Kernel command line:", 0) == 0) {
                if (line.find("enforcing=0") != std::string_view::npos || line.find("androidboot.selinux=permissive") != std::string_view::npos) {
                    context.seLinuxState = AnalysisContext::SELinuxState::Permissive;
                    return;
                }
            }

            std::string_view key, value;
            parse_property_line(line, key, value);
            if (key == "ro.boot.selinux" && value == "permissive") {
                    context.seLinuxState = AnalysisContext::SELinuxState::Permissive;
                    return;
            }

            if (line.find("avc: denied") != std::string_view::npos) {
                if (line.find("permissive=1") != std::string_view::npos) {
                    context.seLinuxState = AnalysisContext::SELinuxState::Permissive;
                }
            }
        }

        void SELinuxStateRule::finalize(ReportData& report, AnalysisContext& context) {
            if (context.seLinuxState == AnalysisContext::SELinuxState::Permissive) {
                report.seLinuxStatus = "Permissive";
                std::string report_str = "SELinux is in Permissive mode, which disables key security features.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            } else {
                report.seLinuxStatus = "Enforcing";
            }
        }

        int SELinuxStateRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Permissive mode") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> CustomSePolicyRule::getTargetSections() const { return {"LOGCAT", "KERNEL LOG", "LAST KMSG"}; }
        DetectionCategory CustomSePolicyRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void CustomSePolicyRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("custom sepolicy") != std::string_view::npos || line.find("Magisk sepolicy") != std::string_view::npos) {
                std::string report_str = "Custom SELinux policy detected, indicating system-level modification.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int CustomSePolicyRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Custom SELinux policy") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> DmVerityRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG"}; }
        DetectionCategory DmVerityRule::getTargetCategory() const { return DetectionCategory::FileSystemAndMounts; }
        
        void DmVerityRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("dm_verity_init") != std::string_view::npos && line.find("error") != std::string_view::npos) {
                std::string report_str = "System Integrity: dm-verity corruption error detected.";
                if (report.detections[DetectionCategory::FileSystemAndMounts].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int DmVerityRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("dm-verity corruption error") != std::string::npos) return 4;
            return 0;
        }

        std::vector<std::string> KernelRule::getTargetSections() const { return {"KERNEL LOG", "LAST KMSG"}; }
        DetectionCategory KernelRule::getTargetCategory() const { return DetectionCategory::CustomBuild; }
        
        void KernelRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (report.buildFingerprint.empty() && line.rfind("Linux version ", 0) == 0) {
                std::string lower_line(line);
                std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (lower_line.find("build-user@build-host") == std::string::npos || lower_line.find("-perf") != std::string::npos) {
                    std::string report_str = "Custom Kernel Detected: " + std::string(line);
                    if (report.detections[DetectionCategory::CustomBuild].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int KernelRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Custom Kernel Detected") != std::string::npos) return 2;
            return 0;
        }

        SuspiciousModulesRule::SuspiciousModulesRule() : blacklist({"tcpdump", "nethunter", "kalilinux", "magisk", "ksu", "zygisk", "wireguard"}) {}

        std::vector<std::string> SuspiciousModulesRule::getTargetSections() const { return {"LSMOD"}; }
        DetectionCategory SuspiciousModulesRule::getTargetCategory() const { return DetectionCategory::Anomalies; }
        
        void SuspiciousModulesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            for (const auto& mod : blacklist) {
                if (line.find(mod) != std::string_view::npos) {
                    std::string report_str = "Suspicious Kernel Module loaded: " + std::string(mod);
                    if (report.detections[DetectionCategory::Anomalies].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int SuspiciousModulesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Kernel Module loaded:") != std::string::npos) return 3;
            return 0;
        }

        std::vector<std::string> ResetpropRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory ResetpropRule::getTargetCategory() const { return DetectionCategory::RootHidingAndEvasion; }
        
        void ResetpropRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("init") != std::string_view::npos && line.find("Command 'resetprop'") != std::string_view::npos) {
                std::string report_str = "Evasion: resetprop utility executed by init.";
                if (report.detections[DetectionCategory::RootHidingAndEvasion].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int ResetpropRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("resetprop utility executed") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> InitServiceRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory InitServiceRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void InitServiceRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if(line.find("init") != std::string_view::npos && line.find("starting service") != std::string_view::npos && (line.find("magisk") != std::string_view::npos || line.find("ksu") != std::string_view::npos)) {
                std::string report_str = "Init: Starting suspicious service: " + std::string(line);
                if (report.detections[DetectionCategory::AnomalousLogs].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int InitServiceRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Starting suspicious service") != std::string::npos) return 4;
            return 0;
        }

        std::vector<std::string> LinkerAnomalyRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory LinkerAnomalyRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void LinkerAnomalyRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            if (line.find("linker") != std::string_view::npos && line.find("CANNOT LINK") != std::string_view::npos) {
                report_str = "Linker: Library linking error detected: " + std::string(line);
            } else if (line.find("debuggerd") != std::string_view::npos && line.find("crash") != std::string_view::npos) {
                report_str = "Debuggerd: Process crash detected, potential sign of instability or tampering.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int LinkerAnomalyRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("CANNOT LINK") != std::string::npos) return 1;
            if (detectionMessage.find("Process crash detected") != std::string::npos) return 1;
            return 0;
        }

        UserSnippetRule::UserSnippetRule() : pid_dump_regex(R"(----- pid (\d+) at)") {}

        std::vector<std::string> UserSnippetRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory UserSnippetRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void UserSnippetRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            std::smatch match;
            const std::string line_str(line);
            if (std::regex_search(line_str, match, pid_dump_regex)) {
                context.last_pid_dump = match[1].str();
            } else if (!context.last_pid_dump.empty() && line.find("Cmd line: zygote") != std::string_view::npos) {
                std::string report_str = "Zygote process dump found (PID: " + context.last_pid_dump + ")";
                if (report.detections[DetectionCategory::AnomalousLogs].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
                context.last_pid_dump.clear();
            } else if (line.find("-----") == std::string_view::npos && line.find("Cmd line:") == std::string_view::npos) {
                context.last_pid_dump.clear();
            }
        }
        
        int UserSnippetRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Zygote process dump found") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> ZygoteForkSpamRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory ZygoteForkSpamRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }

        void ZygoteForkSpamRule::processLine(std::string_view line, ReportData&, AnalysisContext& context) {
            if (line.find("Zygote") != std::string_view::npos && line.find("Forked child process") != std::string_view::npos) {
                context.zygote_fork_count++;
            }
        }

        void ZygoteForkSpamRule::finalize(ReportData& report, AnalysisContext& context) {
            const int FORK_SPAM_THRESHOLD = 50;
            if (context.zygote_fork_count > FORK_SPAM_THRESHOLD) {
                std::string report_str = "Anomalous Zygote Activity: Zygote forked " + std::to_string(context.zygote_fork_count) + " times, which may indicate process spam or instability.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }

        int ZygoteForkSpamRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Anomalous Zygote Activity") != std::string::npos) return 1;
            return 0;
        }

        std::vector<std::string> KeymasterLogRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG"}; }
        DetectionCategory KeymasterLogRule::getTargetCategory() const { return DetectionCategory::SuspiciousProperties; }
        
        void KeymasterLogRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            if (context.bootloaderStateConfirmedByKernel) return;

            if ((line.find("Keymaster") != std::string_view::npos || line.find("keystore") != std::string_view::npos) &&
                (line.find("device is unlocked") != std::string_view::npos)) {
                    std::string report_str = "High-Confidence: Keymaster log confirms device is unlocked.";
                    if (report.detections[getTargetCategory()].insert(report_str).second) {
                        context.verifiedBootState = "unlocked (keymaster)";
                        context.bootloaderStateConfirmedByKernel = true;
                        report.totalScore += getScore(report_str);
                    }
            }
            if (line.find("Attestation key provisioned") != std::string_view::npos && line.find("boot state: UNVERIFIED") != std::string_view::npos) {
                    std::string report_str = "High-Confidence: Keystore attestation reports UNVERIFIED boot state.";
                    if (report.detections[getTargetCategory()].insert(report_str).second) {
                        context.verifiedBootState = "unlocked (attestation)";
                        context.bootloaderStateConfirmedByKernel = true;
                        report.totalScore += getScore(report_str);
                    }
            }
        }
        
        int KeymasterLogRule::getScore(const std::string& detectionMessage) const {
            return 6;
        }

        std::vector<std::string> TrickyStoreLogRule::getTargetSections() const {
            return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"};
        }
        DetectionCategory TrickyStoreLogRule::getTargetCategory() const {
            return DetectionCategory::RootHidingAndEvasion;
        }
        void TrickyStoreLogRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("TrickyStore") != std::string_view::npos) {
                std::string report_str = "TrickyStore log detected.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        int TrickyStoreLogRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("TrickyStore") != std::string::npos) return 5;
            return 0;
        }
    }
}
