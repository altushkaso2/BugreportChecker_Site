#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        std::vector<std::string> PackageManagerRule::getTargetSections() const { return {"DUMPSYS package", "CHECKIN PACKAGE"}; }
        DetectionCategory PackageManagerRule::getTargetCategory() const { return DetectionCategory::AppAnalysis; }

        void PackageManagerRule::process_current_package(ReportData& report, AnalysisContext& context) {
            if (context.current_package_name.empty()) return;

            if (context.current_package_name == "com.facebook.lite") {
                std::string report_str = "Suspicious App Present: com.facebook.lite detected (Can be used for cheats, e.g., Elysium).";
                if (report.detections[DetectionCategory::Anomalies].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
            if (!context.current_seinfo.empty() && context.current_seinfo.find("untrusted_app") == std::string::npos) {
                std::string report_str = "App '" + context.current_package_name + "' has non-standard SELinux context: " + context.current_seinfo;
                if (report.detections[DetectionCategory::AppAnalysis].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }

            context.current_package_name.clear();
            context.current_seinfo.clear();
            is_hidden = false;
        }

        void PackageManagerRule::processLine(std::string_view line, ReportData& report, AnalysisContext& context) {
            if (line.rfind("  Package [", 0) == 0) {
                process_current_package(report, context);

                std::string_view pkg_part = line.substr(11);
                size_t end_pos = pkg_part.find(']');
                if (end_pos != std::string_view::npos) {
                    context.current_package_name = std::string(pkg_part.substr(0, end_pos));
                }
            } else if (!context.current_package_name.empty() && line.find("hidden=true") != std::string_view::npos) {
                is_hidden = true;
            } else if (!context.current_package_name.empty() && line.find("seinfo=") != std::string_view::npos) {
                auto seinfo_pos = line.find("seinfo=");
                std::string_view seinfo_val = line.substr(seinfo_pos + 7);
                if (seinfo_val.find(' ') != std::string_view::npos) {
                    seinfo_val = seinfo_val.substr(0, seinfo_val.find(' '));
                }
                context.current_seinfo = std::string(seinfo_val);
            }
        }

        void PackageManagerRule::finalize(ReportData& report, AnalysisContext& context) {
            process_current_package(report, context);
        }

        int PackageManagerRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("non-standard SELinux context") != std::string::npos) return 2;
            if (detectionMessage.find("com.facebook.lite") != std::string::npos) return 0;
            return 0;
        }

        AppRootUsageRule::AppRootUsageRule() : su_log_regex(R"(pkg=(.+?)\s|cmd=(.+?)\s)") {}

        std::vector<std::string> AppRootUsageRule::getTargetSections() const { return {"LOGCAT", "SYSTEM LOG", "LAST LOGCAT"}; }
        DetectionCategory AppRootUsageRule::getTargetCategory() const { return DetectionCategory::AppAnalysis; }

        void AppRootUsageRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("su") != std::string_view::npos && (line.find("allow") != std::string_view::npos || line.find("grant") != std::string_view::npos)) {
                std::smatch match;
                if (std::regex_search(std::string(line), match, su_log_regex)) {
                    std::string app = match[1].matched ? match[1].str() : match[2].str();
                    if(!app.empty()) {
                        std::string report_str = "Root Usage: App '" + app + "' was granted root access.";
                        if (report.detections[DetectionCategory::AppAnalysis].insert(report_str).second) {
                            report.totalScore += getScore(report_str);
                        }
                    }
                }
            }
        }

        int AppRootUsageRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Root Usage: App") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> TracerPidRule::getTargetSections() const { return {"PROCESSES AND THREADS"}; }
        DetectionCategory TracerPidRule::getTargetCategory() const { return DetectionCategory::Anomalies; }

        void TracerPidRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.rfind("TracerPid:", 0) == 0) {
                std::string_view value_sv = line.substr(10);
                value_sv.remove_prefix((std::min)(value_sv.find_first_not_of(" \t"), value_sv.size()));
                if(value_sv != "0") {
                    std::string report_str = "CRITICAL: Active process tracer detected (TracerPid is not 0). This may indicate Frida or other instrumentation frameworks.";
                    if (report.detections[DetectionCategory::Anomalies].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }

        int TracerPidRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("TracerPid is not 0") != std::string::npos) return 7;
            return 0;
        }

        std::vector<std::string> TrickyStoreProcessRule::getTargetSections() const {
            return {"PROCESSES AND THREADS"};
        }
        DetectionCategory TrickyStoreProcessRule::getTargetCategory() const {
            return DetectionCategory::RootHidingAndEvasion;
        }
        void TrickyStoreProcessRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("TrickyStore") != std::string_view::npos) {
                std::string report_str = "TrickyStore process detected.";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        int TrickyStoreProcessRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("TrickyStore") != std::string::npos) return 6;
            return 0;
        }
    }
}
