#pragma once

#include "Common.h"
#include "core/Core.h"
#include "core/IDetectionRule.h"

namespace Core {
    class ReportAnalyzer {
    private:
        std::vector<std::unique_ptr<IDetectionRule>> rules;
        std::map<std::string, std::pair<std::streampos, std::streampos>> build_section_index(const fs::path& reportPath, long long file_size, const std::function<void(float)>& progress_callback) const;
        std::map<std::string, std::vector<IDetectionRule*>> map_rules_to_sections() const;
        void run_correlation_engine(ReportData& report, AnalysisContext& context) const;
        void analyze_proc_mountinfo(const fs::path& procDir, const std::map<std::string, std::vector<IDetectionRule*>>& rule_map, ReportData& result, AnalysisContext& context) const;

    public:
        ReportAnalyzer();
        void analyze(const fs::path& extractedReportDir, const std::function<void(float)>& progress_callback, ReportData& result) const;
    };
}
