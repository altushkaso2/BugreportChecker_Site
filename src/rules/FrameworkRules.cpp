#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        ProhibitedPackagesRule::ProhibitedPackagesRule() : threat_lexicon({
            {"com.topjohnwu.magisk", {"Magisk Manager app detected", DetectionCategory::ProhibitedPackages}},
            {"io.github.huskydg.magisk", {"Magisk (HuskyDG Fork) app detected", DetectionCategory::ProhibitedPackages}},
            {"com.topjohnwu.magisk.alpha", {"Magisk Alpha app detected", DetectionCategory::ProhibitedPackages}},
            {"io.github.vvb2060.magisk", {"Magisk (non-stable) app detected", DetectionCategory::ProhibitedPackages}},
            {"me.weishu.kernelsu", {"KernelSU Manager detected", DetectionCategory::ProhibitedPackages}},
            {"com.rifsxd.ksunext", {"KernelSU Next app detected", DetectionCategory::ProhibitedPackages}},
            {"eu.chainfire.supersu", {"SuperSU app detected", DetectionCategory::ProhibitedPackages}},
            {"com.koushikdutta.superuser", {"Koushik Dutta Superuser app detected", DetectionCategory::ProhibitedPackages}},
            {"com.thirdparty.superuser", {"Third party Superuser app detected", DetectionCategory::ProhibitedPackages}},
            {"com.noshufou.android.su", {"Noshufou Superuser app detected", DetectionCategory::ProhibitedPackages}},
            {"com.kingroot.kinguser", {"KingRoot app detected", DetectionCategory::ProhibitedPackages}},
            {"com.kingo.root", {"KingoRoot app detected", DetectionCategory::ProhibitedPackages}},
            {"com.github.capntrips.kernelflasher", {"KernelFlasher app detected", DetectionCategory::ProhibitedPackages}},
            {"com.twj.wksu", {"WKSU app detected", DetectionCategory::ProhibitedPackages}},
            {"com.sukisu.ultra", {"SukiSU app detected", DetectionCategory::ProhibitedPackages}},
            {"de.robv.android.xposed.installer", {"Xposed Installer app detected", DetectionCategory::ProhibitedPackages}},
            {"org.lsposed.manager", {"LSPosed Manager app detected", DetectionCategory::ProhibitedPackages}},
            {"me.weishu.exp", {"Exposed Framework app detected", DetectionCategory::ProhibitedPackages}},
            {"com.keramidas.TitaniumBackup", {"TitaniumBackup app detected", DetectionCategory::ProhibitedPackages}},
            {"org.adaway", {"AdAway app detected", DetectionCategory::ProhibitedPackages}},
            {"com.tsng.hidemyapplist", {"Hide My Applist app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.f1player", {"F1 VM (Virtual Machine) app detected", DetectionCategory::ProhibitedPackages}},
            {"com.dualspace.multispace", {"Dual Space (Multi Account) app detected", DetectionCategory::ProhibitedPackages}},
            {"com.amphoras.hidemyroot", {"Hide My Root app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.amphoras.hidemyrootadfree", {"Hide My Root (Ad-free) app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.deltazefiro.amarok", {"Amarok root hiding app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.saurik.substrate", {"Substrate app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.zachspong.temprootremovejb", {"Temporary Root Remove JB app detected", DetectionCategory::RootHidingAndEvasion}},
            {"org.kdrag0n.safetynetfix", {"SafetyNet Fix module app detected", DetectionCategory::RootHidingAndEvasion}},
            {"com.chelpus.luckypatcher", {"Lucky Patcher app detected", DetectionCategory::ProhibitedPackages}},
            {"com.dimonvideo.luckypatcher", {"Lucky Patcher (DimonVideo) app detected", DetectionCategory::ProhibitedPackages}},
            {"catch_.me_.if_.you_.can_", {"Catch Me If You Can app detected", DetectionCategory::ProhibitedPackages}},
            {"com.cih.game_cih", {"Game CIH app detected", DetectionCategory::ProhibitedPackages}},
            {"org.sbtools.gamehack", {"SB Game Hacker app detected", DetectionCategory::ProhibitedPackages}},
            {"com.sbgamehacker", {"SB Game Hacker (legacy) app detected", DetectionCategory::ProhibitedPackages}},
            {"com.gameguardian", {"Game Guardian app detected", DetectionCategory::ProhibitedPackages}},
            {"com.xmodgame", {"Xmodgames app detected", DetectionCategory::ProhibitedPackages}},
            {"com.lody.virtual", {"VirtualXposed / Parallel Space app detected", DetectionCategory::ProhibitedPackages}},
            {"com.excelliance.multiaccount", {"Multi Parallel app detected", DetectionCategory::ProhibitedPackages}},
            {"org.giskard.magisk", {"Giskard root detected", DetectionCategory::RootAndFrameworks}},
            {"moe.shizuku.privileged.api", {"Shizuku app detected", DetectionCategory::AppAnalysis}},
            {"com.termux", {"Termux app detected", DetectionCategory::AppAnalysis}},
            {"com.exynos.abuse", {"Exynos Abuse app detected", DetectionCategory::AppAnalysis}},
            {"com.google.android.apps.playconsole", {"Play Console app detected", DetectionCategory::AppAnalysis}},
            {"com.google.android.gms.playconsole", {"Play Console (Legacy) app detected", DetectionCategory::AppAnalysis}},
            {"meow.helper", {"Meow Helper app detected", DetectionCategory::ProhibitedPackages}},
            {"com.axlebolt.standoff2.xiaomi", {"Plutonium (Standoff 2 Cheat) package detected", DetectionCategory::ProhibitedPackages}}
        }) {}

        std::vector<std::string> ProhibitedPackagesRule::getTargetSections() const {
            return { "DUMPSYS package", "CHECKIN PACKAGE", "LOGCAT", "SYSTEM LOG" };
        }
        DetectionCategory ProhibitedPackagesRule::getTargetCategory() const { return DetectionCategory::ProhibitedPackages; }
        
        void ProhibitedPackagesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            for (const auto& [pkg, info] : threat_lexicon) {
                if (line.find(pkg) != std::string_view::npos) {
                    const auto& [message, category] = info;
                    if (report.detections[category].insert(message).second) {
                        report.totalScore += getScore(message);
                    }
                    if (pkg == "meow.helper") {
                        const std::string evasion_message = "Meow Helper detected (Evasion Tactic)";
                        const auto evasion_category = DetectionCategory::RootHidingAndEvasion;
                        if (report.detections[evasion_category].insert(evasion_message).second) {
                            report.totalScore += getScore(evasion_message);
                        }
                    }
                }
            }
        }
        
        int ProhibitedPackagesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Magisk") != std::string::npos || detectionMessage.find("KernelSU") != std::string::npos || detectionMessage.find("SukiSU") != std::string::npos || detectionMessage.find("Meow Helper") != std::string::npos) return 4;
            if (detectionMessage.find("Xposed") != std::string::npos || detectionMessage.find("LSPosed") != std::string::npos) return 4;
            if (detectionMessage.find("Hide My Root") != std::string::npos || detectionMessage.find("SafetyNet Fix") != std::string::npos || detectionMessage.find("Amarok") != std::string::npos) return 3;
            if (detectionMessage.find("Lucky Patcher") != std::string::npos || detectionMessage.find("Game Guardian") != std::string::npos || detectionMessage.find("VirtualXposed") != std::string::npos) return 4;
            if (detectionMessage.find("Plutonium (Standoff 2 Cheat)") != std::string::npos) return 4;
            if (detectionMessage.find("TitaniumBackup") != std::string::npos) return 2;
            if (detectionMessage.find("AdAway") != std::string::npos) return 1;
            if (detectionMessage.find("Hide My Applist") != std::string::npos) return 3;
            if (detectionMessage.find("Virtual Machine") != std::string::npos || detectionMessage.find("Dual Space") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> ZygoteParentRule::getTargetSections() const { return {"PROCESSES AND THREADS"}; }
        DetectionCategory ZygoteParentRule::getTargetCategory() const { return DetectionCategory::Anomalies; }
        
        void ZygoteParentRule::processLine(std::string_view line, ReportData&, AnalysisContext& context) {
            auto next_token = [](std::string_view& sv) -> std::string_view {
                sv.remove_prefix((std::min)(sv.find_first_not_of(" \t"), sv.size()));
                size_t pos = sv.find_first_of(" \t");
                std::string_view token = sv.substr(0, pos);
                sv.remove_prefix(pos == std::string_view::npos ? sv.size() : pos + 1);
                return token;
            };
            std::string_view line_sv = line;
            std::string_view pid_sv, ppid_sv;
            bool pid_found = false;
            while(!line_sv.empty()) {
                std::string_view token = next_token(line_sv);
                if (token.empty()) continue;
                bool is_numeric = !token.empty() && std::all_of(token.begin(), token.end(), [](char c){ return std::isdigit(static_cast<unsigned char>(c)); });
                if (is_numeric) {
                    if (!pid_found) {
                        pid_sv = token;
                        pid_found = true;
                    } else {
                        ppid_sv = token;
                        break;
                    }
                }
            }
            if (pid_sv.empty() || ppid_sv.empty()) return;
            try {
                int pid = std::stoi(std::string(pid_sv));
                int ppid = std::stoi(std::string(ppid_sv));
                size_t name_pos = line.find_last_of(" \t");
                if (name_pos == std::string_view::npos) return;
                std::string_view name = line.substr(name_pos + 1);
                if (name.find("magiskd") != std::string_view::npos) {
                    context.magiskd_pid = pid;
                } else if (name.find("zygote") != std::string_view::npos) {
                    context.zygote_ppid = ppid;
                }
            } catch(...) {}
        }
        
        void ZygoteParentRule::finalize(ReportData& report, AnalysisContext& context) {
            if (context.magiskd_pid.has_value() && context.zygote_ppid.has_value() && context.magiskd_pid.value() == context.zygote_ppid.value()) {
                std::string report_str = "Zygisk Anomaly: Zygote parent process is magiskd.";
                if (report.detections[DetectionCategory::Anomalies].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int ZygoteParentRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Zygote parent process is magiskd") != std::string::npos) return 7;
            return 0;
        }

        RootActivityRule::RootActivityRule() 
            : whitelist({ "init", "kthreadd", "adbd", "lmkd", "logd", "servicemanager", "ueventd", "vold", "healthd", "installd", "storaged", "netd", "surfaceflinger", "wificond", "zygote", "zygote64" }),
              blacklist({"frida-server", "ksud", "zygiskd", "magiskd", "apatchd"}) {}

        std::vector<std::string> RootActivityRule::getTargetSections() const { return {"PROCESSES AND THREADS"}; }
        DetectionCategory RootActivityRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void RootActivityRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            for (const auto& proc_name : blacklist) {
                if (line.find(proc_name) != std::string_view::npos) {
                    std::string report_str = "Root Process: '" + std::string(proc_name) + "' process detected.";
                    if (report.detections[getTargetCategory()].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }

            std::string_view line_for_root_check = line;
            line_for_root_check.remove_prefix((std::min)(line_for_root_check.find_first_not_of(" \t"), line_for_root_check.size()));

            if (line_for_root_check.rfind("root", 0) == 0) {
                size_t name_pos = line.find_last_of(" \t");
                if (name_pos == std::string_view::npos) return;

                std::string_view name = line.substr(name_pos + 1);
                size_t basename_pos = name.find_last_of('/');
                std::string_view basename = (basename_pos == std::string_view::npos) ? name : name.substr(basename_pos + 1);

                if (whitelist.find(basename) == whitelist.end()) {
                    context.suspicious_root_procs.insert(std::string(basename));
                }
            }
        }
        
        void RootActivityRule::finalize(ReportData& report, AnalysisContext& context) {
            for(const auto& proc : context.suspicious_root_procs) {
                std::string report_str = "Suspicious Root Process: Non-standard process '" + proc + "' running as root.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int RootActivityRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Root Process:") != std::string::npos) return 6;
            if (detectionMessage.find("Suspicious Root Process:") != std::string::npos) return 3;
            return 0;
        }

        std::vector<std::string> SelinuxContextRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "KERNEL LOG", "PROCESSES AND THREADS"}; }
        DetectionCategory SelinuxContextRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void SelinuxContextRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            if (line.find("u:object_r:magisk_file:s0") != std::string_view::npos) {
                report_str = "SELinux: Found 'magisk_file' context, a strong indicator of Magisk.";
            } else if (line.find("u:r:magisk:s0") != std::string_view::npos) {
                report_str = "SELinux: Active Magisk process context detected.";
            } else if (line.find("u:r:magisk_alpha:s0") != std::string_view::npos) {
                report_str = "SELinux: Active Magisk Alpha process context detected.";
            } else if (line.find("u:r:apatch:s0") != std::string_view::npos) {
                report_str = "SELinux: Active APatch process context detected.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int SelinuxContextRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("'magisk_file'") != std::string::npos) return 4;
            if (detectionMessage.find("Active Magisk process context") != std::string::npos) return 6;
            if (detectionMessage.find("Active APatch process context") != std::string::npos) return 6;
            return 0;
        }

        std::vector<std::string> LoadedLibrariesRule::getTargetSections() const { return {"PROCESSES AND THREADS"}; }
        DetectionCategory LoadedLibrariesRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void LoadedLibrariesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            if (line.find("libzygisk.so") != std::string_view::npos) {
                report_str = "Zygisk library loaded into a process.";
            } else if (line.find("XposedBridge.jar") != std::string_view::npos) {
                report_str = "Xposed framework artifact loaded: XposedBridge.jar";
            } else if (line.find("libfrida-gadget.so") != std::string_view::npos || line.find("libfrida-agent.so") != std::string_view::npos) {
                report_str = "Instrumentation Framework: Frida library loaded into a process.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int LoadedLibrariesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Zygisk library loaded") != std::string::npos) return 5;
            if (detectionMessage.find("Xposed framework artifact") != std::string::npos) return 5;
            if (detectionMessage.find("Frida library loaded") != std::string::npos) return 7;
            return 0;
        }

        FrameworkRule::FrameworkRule() 
            : lsposed_version_regex(R"(LSPosed version ([\d\.]+) )"), 
              lsposed_target_regex(R"(target=(.+?)\s)") {}

        std::vector<std::string> FrameworkRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory FrameworkRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void FrameworkRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            std::string report_str;
            if (line.find("LSPosed") != std::string_view::npos) {
                context.lastDetectedFramework = "LSPosed";
                std::smatch match;
                const std::string line_str(line);
                if (std::regex_search(line_str, match, lsposed_version_regex)) {
                    report_str = "LSPosed framework detected (Version: " + match[1].str() + ")";
                }
                if (std::regex_search(line_str, match, lsposed_target_regex)) {
                    std::string hook_report_str = "LSPosed Hook: Module active for app '" + match[1].str() + "'.";
                    if (report.detections[DetectionCategory::AppAnalysis].insert(hook_report_str).second) {
                       report.totalScore += getScore(hook_report_str);
                    }
                }
            }
            else if (line.find("Xposed") != std::string_view::npos || line.find("EdXposed") != std::string_view::npos) {
                report_str = "Xposed/EdXposed framework log tag detected.";
            }
            else if (line.find("Shamiko") != std::string_view::npos) {
                context.lastDetectedFramework = "Shamiko";
                report_str = "Shamiko root hiding module log tag detected.";
            }
            else if (line.find("MagiskHide") != std::string_view::npos) {
                report_str = "Legacy MagiskHide log tag detected.";
            }
            else if (line.find("Magisk") != std::string_view::npos && line.find("Alpha") != std::string_view::npos) {
                report_str = "Magisk Alpha log tag detected.";
            }
            else if (line.find("zygisk") != std::string_view::npos && line.find("ptrace") != std::string_view::npos) {
                context.lastDetectedFramework = "Zygisk";
                report_str = "Zygisk ptrace activity detected in logs.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int FrameworkRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("LSPosed framework detected") != std::string::npos) return 5;
            if (detectionMessage.find("Xposed/EdXposed framework") != std::string::npos) return 4;
            if (detectionMessage.find("Shamiko root hiding module") != std::string::npos) return 5;
            if (detectionMessage.find("MagiskHide log tag") != std::string::npos) return 3;
            if (detectionMessage.find("Magisk Alpha log tag") != std::string::npos) return 6;
            if (detectionMessage.find("LSPosed Hook") != std::string::npos) return 2;
            if (detectionMessage.find("Zygisk ptrace activity") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> EnvironmentRule::getTargetSections() const { return {"PROCESSES AND THREADS", "PRINTENV"}; }
        DetectionCategory EnvironmentRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void EnvironmentRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            if (line.find("PATH") != std::string_view::npos && line.find("/data/adb/magisk") != std::string_view::npos) {
                report_str = "Magisk path found in PATH environment variable.";
            } else if (line.find("LD_PRELOAD") != std::string_view::npos) {
                report_str = "LD_PRELOAD environment variable is set, indicating potential code injection.";
            }
            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int EnvironmentRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Magisk path found") != std::string::npos) return 4;
            if (detectionMessage.find("LD_PRELOAD") != std::string::npos) return 5;
            return 0;
        }

        KernelSuLogRule::KernelSuLogRule()
            : susfs_regex(R"(susfs is initialized! version: (v[\d\.]+))"),
              init_regex(R"(KernelSU: (\S+init) argc:)") {}

        std::vector<std::string> KernelSuLogRule::getTargetSections() const { return {"KERNEL LOG", "LAST KMSG"}; }
        DetectionCategory KernelSuLogRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void KernelSuLogRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("KernelSU") == std::string_view::npos && line.find("susfs") == std::string_view::npos) return;
            std::smatch match;
            const std::string line_str(line);
            std::string report_str;
            if (std::regex_search(line_str, match, init_regex)) {
                report_str = "KernelSU init interception detected for " + match[1].str();
            }
            else if (line.find("KernelSU: KPROBES is disabled") != std::string_view::npos) {
                report_str = "KernelSU dmesg trace found (KPROBES disabled).";
            }
            else if (std::regex_search(line_str, match, susfs_regex)) {
                report_str = "KernelSU module (susfs) detected, version " + match[1].str();
            }
            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int KernelSuLogRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("KernelSU init interception") != std::string::npos) return 6;
            if (detectionMessage.find("KernelSU dmesg trace") != std::string::npos) return 4;
            if (detectionMessage.find("KernelSU module (susfs) detected") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> RunningServicesRule::getTargetSections() const { return {"DUMPSYS activity services"}; }
        DetectionCategory RunningServicesRule::getTargetCategory() const { return DetectionCategory::ProhibitedPackages; }
        
        void RunningServicesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("ServiceRecord{") == std::string_view::npos) return;

            const static std::map<std::string_view, DetectionCategory> suspicious_services = {
                {"com.topjohnwu.magisk", DetectionCategory::RootAndFrameworks},
                {"me.weishu.kernelsu", DetectionCategory::RootAndFrameworks},
                {"org.lsposed.manager", DetectionCategory::RootAndFrameworks},
                {"io.github.vvb2060.magisk", DetectionCategory::RootAndFrameworks},
                {"com.chelpus.luckypatcher", DetectionCategory::ProhibitedPackages},
                {"com.android.vending.billing.InAppBillingService.LACK", DetectionCategory::ProhibitedPackages},
                {"org.giskard.magisk", DetectionCategory::RootAndFrameworks},
                {"moe.shizuku.privileged.api", DetectionCategory::AppAnalysis}
            };

            for (const auto& [service_pkg, category] : suspicious_services) {
                if (line.find(service_pkg) != std::string_view::npos) {
                    std::string report_str = "Active service from suspicious package detected: " + std::string(service_pkg);
                    if (report.detections[category].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int RunningServicesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Active service from suspicious package") != std::string::npos) return 4;
            return 0;
        }

        std::vector<std::string> ZygoteAnomalyRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT", "PROCESSES AND THREADS"}; }
        DetectionCategory ZygoteAnomalyRule::getTargetCategory() const { return DetectionCategory::AnomalousLogs; }
        
        void ZygoteAnomalyRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            std::string report_str;
            if (line.find("Zygote") != std::string_view::npos) {
                if (line.find("crash") != std::string_view::npos || line.find("restarting") != std::string_view::npos || line.find("restarting system server") != std::string_view::npos) {
                    if (!context.lastDetectedFramework.empty()) {
                        std::string cr_report_str = "CORRELATED: Zygote restarted shortly after " + context.lastDetectedFramework + " activity, indicating a module hot-swap.";
                        if (report.detections[getTargetCategory()].insert(cr_report_str).second) {
                            report.totalScore += 5;
                        }
                        context.lastDetectedFramework.clear();
                    } else {
                        report_str = "Zygote crash or restart detected.";
                    }
                }
                if (line.find("Starting Magisk services") != std::string_view::npos || line.find("mount --bind") != std::string_view::npos) {
                    report_str = "Magisk Zygisk service detected via logs.";
                }
            }
            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int ZygoteAnomalyRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Zygote crash or restart") != std::string::npos) return 3;
            if (detectionMessage.find("Magisk Zygisk service detected") != std::string::npos) return 5;
            return 0;
        }

        std::vector<std::string> TombstoneRule::getTargetSections() const { return {"TOMBSTONES", "CRASH LOG", "SYSTEM CRASHES"}; }
        DetectionCategory TombstoneRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void TombstoneRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            const static std::set<std::string_view> framework_traces = {"libxposed", "XposedBridge", "libfrida-gadget", "frida-agent", "libsubstrate", "libzygisk"};
            for (const auto& trace : framework_traces) {
                if (line.find(trace) != std::string_view::npos) {
                    std::string report_str = "High-Confidence: Hooking framework trace '" + std::string(trace) + "' found in crash log.";
                    if (report.detections[getTargetCategory()].insert(report_str).second) {
                       report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int TombstoneRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Hooking framework trace") != std::string::npos) return 7;
            return 0;
        }

    }
}
