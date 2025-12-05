#include <emscripten/bind.h>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <map>
#include "analyzer/ReportAnalyzer.h"
#include "core/Core.h"

using namespace emscripten;
namespace fs = std::filesystem;

std::string getCategoryName(Core::DetectionCategory category) {
    static const std::map<Core::DetectionCategory, std::string> names = {
        {Core::DetectionCategory::RootAndFrameworks, "Root & Frameworks"},
        {Core::DetectionCategory::RootHidingAndEvasion, "Root Hiding & Evasion"},
        {Core::DetectionCategory::FileSystemAndMounts, "File System & Mounts"},
        {Core::DetectionCategory::SuspiciousProperties, "Suspicious Properties"},
        {Core::DetectionCategory::Anomalies, "Behavioral Anomalies"},
        {Core::DetectionCategory::CustomBuild, "Custom Build"},
        {Core::DetectionCategory::AnomalousLogs, "Anomalous System Logs"},
        {Core::DetectionCategory::ProhibitedPackages, "Prohibited Packages"},
        {Core::DetectionCategory::AppAnalysis, "Application Analysis"}
    };
    auto it = names.find(category);
    return (it != names.end()) ? it->second : "Unknown Category";
}

std::string analyzeWrapper(std::string filename) {
    std::stringstream ss;
    std::streambuf* old_cout = std::cout.rdbuf(ss.rdbuf());
    std::streambuf* old_cerr = std::cerr.rdbuf(ss.rdbuf());

    try {
        Core::ReportAnalyzer analyzer;
        Core::ReportData data;
        fs::path fpath(filename);
        
        analyzer.analyze(fpath.parent_path(), [](float){}, data);

        ss << "=== REPORT ANALYSIS RESULT ===\n\n";
        ss << "Model: " << (data.model.empty() ? "N/A" : data.model) << "\n";
        ss << "Android Ver: " << (data.androidVersion.empty() ? "N/A" : data.androidVersion) << "\n";
        if (!data.magiskVersion.empty()) ss << "Magisk: " << data.magiskVersion << "\n";
        ss << "Bootloader: " << (data.bootloaderStatus.empty() ? "N/A" : data.bootloaderStatus) << "\n";
        ss << "Fingerprint: " << (data.buildFingerprint.empty() ? "N/A" : data.buildFingerprint) << "\n";
        
        ss << "\nRisk Score: " << data.totalScore << "/10\n";
        if (data.totalScore == 0) ss << "Verdict: Clean.\n";
        else if (data.totalScore <= 4) ss << "Verdict: Suspicious.\n";
        else ss << "Verdict: Critical.\n";

        for (const auto& [category, detections] : data.detections) {
            if (detections.empty()) continue;
            ss << "\n[" << getCategoryName(category) << "]\n";
            for (const auto& det : detections) {
                ss << "- " << det << "\n";
            }
        }
    } catch (const std::exception& e) {
        ss << "\n[CRITICAL ERROR] " << e.what() << "\n";
    }

    std::cout.rdbuf(old_cout);
    std::cerr.rdbuf(old_cerr);
    return ss.str();
}

EMSCRIPTEN_BINDINGS(module) {
    function("analyzeBugReport", &analyzeWrapper);
}
