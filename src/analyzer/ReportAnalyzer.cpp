#include "analyzer/ReportAnalyzer.h"
#include "rules/Rules.h"

namespace Core {

    ReportAnalyzer::ReportAnalyzer() {
        rules.emplace_back(std::make_unique<Rules::SystemPropertyRule>());
        rules.emplace_back(std::make_unique<Rules::PackageManagerRule>());
        rules.emplace_back(std::make_unique<Rules::ProhibitedPackagesRule>());
        rules.emplace_back(std::make_unique<Rules::ZygoteParentRule>());
        rules.emplace_back(std::make_unique<Rules::RootActivityRule>());
        rules.emplace_back(std::make_unique<Rules::InvalidSelinuxTransitionRule>());
        rules.emplace_back(std::make_unique<Rules::SelinuxContextRule>());
        rules.emplace_back(std::make_unique<Rules::KernelRule>());
        rules.emplace_back(std::make_unique<Rules::MountAnalysisRule>());
        rules.emplace_back(std::make_unique<Rules::ResetpropRule>());
        rules.emplace_back(std::make_unique<Rules::InitServiceRule>());
        rules.emplace_back(std::make_unique<Rules::LinkerAnomalyRule>());
        rules.emplace_back(std::make_unique<Rules::TracerPidRule>());
        rules.emplace_back(std::make_unique<Rules::LoadedLibrariesRule>());
        rules.emplace_back(std::make_unique<Rules::FrameworkRule>());
        rules.emplace_back(std::make_unique<Rules::EnvironmentRule>());
        rules.emplace_back(std::make_unique<Rules::KernelSuLogRule>());
        rules.emplace_back(std::make_unique<Rules::UserSnippetRule>());
        rules.emplace_back(std::make_unique<Rules::SuspiciousBinaryRule>());
        rules.emplace_back(std::make_unique<Rules::SuspiciousPropertiesRule>());
        rules.emplace_back(std::make_unique<Rules::RunningServicesRule>());
        rules.emplace_back(std::make_unique<Rules::SelinuxDenialSpamRule>());
        rules.emplace_back(std::make_unique<Rules::SelinuxNeverallowRule>());
        rules.emplace_back(std::make_unique<Rules::DmVerityRule>());
        rules.emplace_back(std::make_unique<Rules::AppRootUsageRule>());
        rules.emplace_back(std::make_unique<Rules::MagiskModulesRule>());
        rules.emplace_back(std::make_unique<Rules::CustomRecoveryRule>());
        rules.emplace_back(std::make_unique<Rules::FilePermissionsRule>());
        rules.emplace_back(std::make_unique<Rules::SuspiciousModulesRule>());
        rules.emplace_back(std::make_unique<Rules::ZygoteAnomalyRule>());
        rules.emplace_back(std::make_unique<Rules::SELinuxStateRule>());
        rules.emplace_back(std::make_unique<Rules::ZygoteForkSpamRule>());
        rules.emplace_back(std::make_unique<Rules::BootloaderStateRule>());
        rules.emplace_back(std::make_unique<Rules::AdvancedFsRule>());
        rules.emplace_back(std::make_unique<Rules::CustomSePolicyRule>());
        rules.emplace_back(std::make_unique<Rules::RemountRule>());
        rules.emplace_back(std::make_unique<Rules::LogKeywordRule>());
        rules.emplace_back(std::make_unique<Rules::InitRcRule>());
        rules.emplace_back(std::make_unique<Rules::TombstoneRule>());
        rules.emplace_back(std::make_unique<Rules::KeymasterLogRule>());
        rules.emplace_back(std::make_unique<Rules::TrickyStoreProcessRule>());
        rules.emplace_back(std::make_unique<Rules::TrickyStoreLogRule>());
    }

    std::map<std::string, std::pair<std::streampos, std::streampos>> ReportAnalyzer::build_section_index(const fs::path& reportPath, long long file_size, const std::function<void(float)>& progress_callback) const {
        std::map<std::string, std::pair<std::streampos, std::streampos>> index;
        std::ifstream file(reportPath);
        if (!file) return index;
        std::string line;
        std::string current_section;
        std::streampos current_start_pos = 0;
        std::streampos line_start_pos = file.tellg();
        int last_progress = -1;

        while (std::getline(file, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.size() > 12 && line.rfind("------ ", 0) == 0 && line.find(" ------", line.size() - 7) != std::string::npos) {
                std::string_view title_sv = line;
                title_sv.remove_prefix(7);
                title_sv.remove_suffix(7);
                if (!current_section.empty()) index[current_section] = {current_start_pos, line_start_pos};
                current_section = std::string(title_sv);
                current_start_pos = file.tellg();
            }
            line_start_pos = file.tellg();

            int progress = (file_size > 0) ? static_cast<int>(20.0f * static_cast<float>(line_start_pos) / file_size) : 0;
            if (progress != last_progress) {
                progress_callback(static_cast<float>(progress));
                last_progress = progress;
            }
        }
        if (!current_section.empty()) {
            file.seekg(0, std::ios::end);
            index[current_section] = {current_start_pos, file.tellg()};
        }
        return index;
    }

    std::map<std::string, std::vector<IDetectionRule*>> ReportAnalyzer::map_rules_to_sections() const {
        std::map<std::string, std::vector<IDetectionRule*>> map;
        for (const auto& rule : rules) {
            for (const auto& section : rule->getTargetSections()) {
                map[section].push_back(rule.get());
            }
        }
        return map;
    }

    void ReportAnalyzer::run_correlation_engine(ReportData& report, AnalysisContext& context) const {
        bool trickyStoreDetected = false;
        
        auto it = report.detections.find(DetectionCategory::RootHidingAndEvasion);
        if (it != report.detections.end()) {
            for (const auto& finding : it->second) {
                if (finding.find("TrickyStore") != std::string::npos) {
                    trickyStoreDetected = true;
                    break; 
                }
            }
        }

        if (trickyStoreDetected) {
            report.bootloaderStatus = "Разблокирован (TrickyStore detected)";
        }
    }

    void ReportAnalyzer::analyze_proc_mountinfo(const fs::path& procDir, const std::map<std::string, std::vector<IDetectionRule*>>& rule_map, ReportData& result, AnalysisContext& context) const {
        result.debugLog.push_back("[DEBUG] Starting mountinfo analysis in " + procDir.string());
        auto it = rule_map.find("MOUNTS");
        if (it == rule_map.end()) {
            result.debugLog.push_back("[DEBUG] No rules found for MOUNTS section, skipping mountinfo scan.");
            return;
        }
        const auto& mount_rules = it->second;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(procDir)) {
                if (entry.is_regular_file() && entry.path().filename() == "mountinfo") {
                    std::ifstream file(entry.path());
                    std::string line;
                    while (std::getline(file, line)) {
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                        std::string_view sv(line);
                        for (auto* rule : mount_rules) {
                            rule->processLine(sv, result, context);
                        }
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            result.debugLog.push_back("[WARNING] Filesystem error while scanning /proc: " + std::string(e.what()));
        }
    }


    void ReportAnalyzer::analyze(const fs::path& extractedReportDir, const std::function<void(float)>& progress_callback, ReportData& result) const {
        
        fs::path reportPath;
        for (const auto& entry : fs::directory_iterator(extractedReportDir)) {
             std::string lower_filename = entry.path().filename().string();
             std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (entry.is_regular_file() && lower_filename.rfind("bugreport", 0) == 0 && lower_filename.find(".txt") != std::string::npos) {
                reportPath = entry.path();
                break;
            }
        }

        if (reportPath.empty()) {
            throw std::runtime_error("No bugreport-*.txt file found in the extracted directory.");
        }

        std::ifstream file_for_size(reportPath, std::ios::binary | std::ios::ate);
        if (!file_for_size) throw std::runtime_error("File not found: " + reportPath.string());
        long long file_size = file_for_size.tellg();
        file_for_size.close();

        auto section_index = build_section_index(reportPath, file_size, progress_callback);
        if (section_index.empty()) {
            std::cout << "\n[WARNING] Could not find any valid sections in the report file.\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        auto rule_map = map_rules_to_sections();

        AnalysisContext context;
        context.debugLogPtr = &result.debugLog;
        std::ifstream file(reportPath);
        std::string line;
        line.reserve(4096);
        int last_progress = 0;

        for (const auto& [section_name_from_file, pos_pair] : section_index) {
            result.debugLog.push_back("[DEBUG] Processing section: '" + section_name_from_file + "'");
            std::vector<IDetectionRule*> active_rules;
            for (const auto& [target_section, rules_for_target] : rule_map) {
                if (section_name_from_file.find(target_section) != std::string::npos) {
                    active_rules.insert(active_rules.end(), rules_for_target.begin(), rules_for_target.end());
                }
            }
            if (active_rules.empty()) continue;
            file.clear();
            file.seekg(pos_pair.first);
            long long section_end_bytes = pos_pair.second;
            while (file.tellg() < section_end_bytes && std::getline(file, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                std::string_view sv(line);
                for (auto* rule : active_rules) {
                    rule->processLine(sv, result, context);
                }

                long long current_pos = file.tellg();
                int progress = (file_size > 0) ? static_cast<int>(20.0f + 70.0f * static_cast<float>(current_pos) / file_size) : 20;
                if (progress != last_progress) {
                    progress_callback(static_cast<float>(progress));
                    last_progress = progress;
                }
            }
        }

        progress_callback(90.0f);
        fs::path procDir = extractedReportDir / "FS" / "proc";
        if (fs::exists(procDir)) {
            analyze_proc_mountinfo(procDir, rule_map, result, context);
        } else {
            result.debugLog.push_back("[DEBUG] FS/proc directory not found, skipping mountinfo scan.");
        }

        progress_callback(95.0f);
        for (const auto& rule : rules) {
            rule->finalize(result, context);
        }
        run_correlation_engine(result, context);
        
        result.totalScore = (std::min)(10, result.totalScore);

        progress_callback(100.0f);
    }
}
