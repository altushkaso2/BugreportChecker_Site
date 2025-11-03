#pragma once

#include "Common.h"
#include "platform/Platform.h"
#include "ui/ConsoleUI.h"
#include "analyzer/ReportAnalyzer.h"
#include "core/Core.h"

#include <optional>
#include <vector>

class Application {
private:
    std::unique_ptr<Platform::IConsole> console_;
    UI::ConsoleUI ui_;
    Core::ReportAnalyzer analyzer_;

    const fs::path TEMP_EXTRACT_DIR = "brc_temp_extract";
    const fs::path TEMP_FINAL_DIR = "brc_temp_final";

    std::vector<fs::path> findBugReports() const;
    void handleAnalysis(bool isDebug, std::optional<fs::path> initial_path = std::nullopt);
    
    void cleanupTempDirs() const;
    bool extractZip(const fs::path& zipPath, const fs::path& extractToDir) const;

public:
    Application();
    ~Application();
    void run(int argc, char* argv[]);
};
