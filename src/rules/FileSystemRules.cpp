#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        std::vector<std::string> MountAnalysisRule::getTargetSections() const { return {"MOUNTS"}; }
        DetectionCategory MountAnalysisRule::getTargetCategory() const { return DetectionCategory::FileSystemAndMounts; }
        
        void MountAnalysisRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            
            if (line.find("/data/adb/modules") != std::string_view::npos && (line.find(" /system ") != std::string_view::npos || line.find(" /vendor ") != std::string_view::npos)) {
                report_str = "Magic Mount: System partition mounted from Magisk modules directory.";
            } else if (line.find("/data/adb") != std::string_view::npos) {
                report_str = "Magisk Directory Mount: /data/adb detected in mounts.";
            } else if (line.find("/data/adb/magisk_alpha") != std::string_view::npos) {
                report_str = "Magisk Alpha directory mount detected.";
            } else if (line.rfind("tmpfs on /sbin", 0) == 0) {
                report_str = "Suspicious Mount: Magisk's tmpfs sbin overlay detected.";
            } else if (line.find("tmpfs magisk") != std::string_view::npos) {
                report_str = "Suspicious Mount: Magisk's tmpfs (magisk) detected.";
            } else if (line.find("/debug_ramdisk/.magisk/worker") != std::string_view::npos) {
                report_str = "Suspicious Mount: Magisk's worker directory detected in mountinfo.";
            } else if (line.find("/system/bin/magisk") != std::string_view::npos && line.find("tmpfs") != std::string_view::npos) {
                report_str = "High-Confidence: Magisk binary is directly mounted over /system/bin/magisk.";
            } else if (line.find("/system/bin") != std::string_view::npos && line.find("tmpfs magisk") != std::string_view::npos) {
                report_str = "High-Confidence: Magisk tmpfs overlay detected on /system/bin.";
            }

            if (!report_str.empty()) {
                if (report.detections[DetectionCategory::FileSystemAndMounts].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int MountAnalysisRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Magic Mount:") != std::string::npos) return 6;
            if (detectionMessage.find("Magisk Directory Mount:") != std::string::npos) return 4;
            if (detectionMessage.find("Magisk Alpha directory mount") != std::string::npos) return 5;
            if (detectionMessage.find("tmpfs sbin overlay") != std::string::npos) return 3;
            if (detectionMessage.find("tmpfs (magisk) detected") != std::string::npos) return 5;
            if (detectionMessage.find("Magisk's worker directory") != std::string::npos) return 6;
            if (detectionMessage.find("Magisk binary is directly mounted") != std::string::npos) return 7;
            if (detectionMessage.find("Magisk tmpfs overlay detected on /system/bin") != std::string::npos) return 7;
            return 0;
        }

        std::vector<std::string> RemountRule::getTargetSections() const { return {"LOGCAT", "KERNEL LOG", "SYSTEM LOG"}; }
        DetectionCategory RemountRule::getTargetCategory() const { return DetectionCategory::FileSystemAndMounts; }
        
        void RemountRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("remount") != std::string_view::npos && line.find("rw") != std::string_view::npos &&
               (line.find("/system") != std::string_view::npos || line.find(" system ") != std::string_view::npos)) {
                std::string report_str = "System partition was remounted as read-write (rw).";
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int RemountRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("remounted as read-write") != std::string::npos) return 6;
            return 0;
        }

        std::vector<std::string> AdvancedFsRule::getTargetSections() const { return {"FILESYSTEM LISTING", "MOUNTS", "LOGCAT"}; }
        DetectionCategory AdvancedFsRule::getTargetCategory() const { return DetectionCategory::FileSystemAndMounts; }
        
        void AdvancedFsRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string report_str;
            if (line.find("/data/adb/magisk.db") != std::string_view::npos) {
                report_str = "High-Confidence: Magisk database file found.";
            } else if (line.find("apatch") != std::string_view::npos) {
                report_str = "High-Confidence: APatch traces found in filesystem or logs.";
            } else if (line.find("re.frida.server") != std::string_view::npos) {
                report_str = "High-Confidence: Frida server configuration files found.";
            } else if (line.find("/dev/ksu") != std::string_view::npos) {
                report_str = "High-Confidence: KernelSU device node found.";
            }

            if (!report_str.empty()) {
                if (report.detections[getTargetCategory()].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int AdvancedFsRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Magisk database") != std::string::npos) return 7;
            if (detectionMessage.find("APatch") != std::string::npos) return 6;
            if (detectionMessage.find("Frida server") != std::string::npos) return 6;
            if (detectionMessage.find("KernelSU device node") != std::string::npos) return 6;
            return 0;
        }

        std::vector<std::string> MagiskModulesRule::getTargetSections() const { return {"FILESYSTEM LISTING"}; }
        DetectionCategory MagiskModulesRule::getTargetCategory() const { return DetectionCategory::AppAnalysis; }
        
        void MagiskModulesRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("/data/adb/modules/") != std::string_view::npos) {
                std::string_view path = line;
                size_t pos = path.find("/data/adb/modules/");
                path.remove_prefix(pos + 18);
                if (!path.empty() && path.find('/') != std::string_view::npos) {
                    path = path.substr(0, path.find('/'));
                    std::string report_str = "Active Magisk/KSU Module: " + std::string(path);
                    if (report.detections[DetectionCategory::AppAnalysis].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int MagiskModulesRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Active Magisk/KSU Module") != std::string::npos) return 3;
            return 0;
        }

        std::vector<std::string> CustomRecoveryRule::getTargetSections() const { return {"FILESYSTEM LISTING"}; }
        DetectionCategory CustomRecoveryRule::getTargetCategory() const { return DetectionCategory::CustomBuild; }
        
        void CustomRecoveryRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.find("/TWRP/") != std::string_view::npos || line.find("/Fox/") != std::string_view::npos) {
                std::string report_str = "Custom Recovery: TWRP or OrangeFox folder detected.";
                if (report.detections[DetectionCategory::CustomBuild].insert(report_str).second) {
                    report.totalScore += getScore(report_str);
                }
            }
        }
        
        int CustomRecoveryRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Custom Recovery") != std::string::npos) return 2;
            return 0;
        }

        FilePermissionsRule::FilePermissionsRule() : whitelist({"/system/bin/ping", "/system/bin/run-as", "/system/xbin/ping"}) {}

        std::vector<std::string> FilePermissionsRule::getTargetSections() const { return {"FILESYSTEM LISTING"}; }
        DetectionCategory FilePermissionsRule::getTargetCategory() const { return DetectionCategory::Anomalies; }
        
        void FilePermissionsRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            if (line.rfind("-rws", 0) == 0 || line.rfind("drws", 0) == 0) {
                size_t pathPos = line.find_last_of(" \t") + 1;
                std::string_view filePath = line.substr(pathPos);
                if (whitelist.find(filePath) == whitelist.end()) {
                    std::string report_str = "Insecure Permissions: SUID bit set on file: " + std::string(line);
                    if (report.detections[DetectionCategory::Anomalies].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int FilePermissionsRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("SUID bit set") != std::string::npos) return 3;
            return 0;
        }

        std::vector<std::string> SuspiciousBinaryRule::getTargetSections() const { return {"FILESYSTEM LISTING", "PROCESSES AND THREADS"}; }
        DetectionCategory SuspiciousBinaryRule::getTargetCategory() const { return DetectionCategory::FileSystemAndMounts; }
        
        void SuspiciousBinaryRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            const static std::set<std::string_view> suspicious_paths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
                "/su/bin/su", "/system/xbin/busybox", "/system/bin/busybox",
                "/system/xbin/magisk", "/system/bin/magisk"
            };
            for (const auto& path : suspicious_paths) {
                if (line.find(path) != std::string_view::npos) {
                    std::string report_str = "Found suspicious binary at: " + std::string(path);
                    if (report.detections[DetectionCategory::FileSystemAndMounts].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int SuspiciousBinaryRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("/su") != std::string::npos || detectionMessage.find("/magisk") != std::string::npos) return 7;
            if (detectionMessage.find("busybox") != std::string::npos) return 2;
            return 0;
        }

        std::vector<std::string> InitRcRule::getTargetSections() const { return {"SYSTEM PROPERTIES", "FILESYSTEM LISTING"}; }
        DetectionCategory InitRcRule::getTargetCategory() const { return DetectionCategory::RootAndFrameworks; }
        
        void InitRcRule::processLine(std::string_view line, ReportData& report, AnalysisContext&) {
            std::string_view trimmed_line = line;
            trimmed_line.remove_prefix((std::min)(trimmed_line.find_first_not_of(" \t"), trimmed_line.size()));

            const static std::set<std::string_view> service_keywords = {"service magisk", "service ksu", "service apatch"};
            for(const auto& keyword : service_keywords) {
                if (trimmed_line.rfind(keyword, 0) == 0) {
                    std::string report_str = "High-Confidence: Root service definition found in init script: " + std::string(line);
                    if (report.detections[getTargetCategory()].insert(report_str).second) {
                        report.totalScore += getScore(report_str);
                    }
                }
            }
        }
        
        int InitRcRule::getScore(const std::string& detectionMessage) const {
            if (detectionMessage.find("Root service definition found") != std::string::npos) return 7;
            return 0;
        }

    }
}
