#include "ui/ConsoleUI.h"

namespace UI {
    ConsoleUI::ConsoleUI(const Platform::IConsole& console) : console_(console) {}

    ConsoleUI::MainMenuOption ConsoleUI::displayMainMenu() const {
        console_.clear();
        console_.write("=====================================\n  DebugReport Checker  \n  (Created by altushkaso2)\n=====================================\n1) Analyze Report (Release)\n2) Analyze Report (Debug)\n3) Exit\n-------------------------------------\nSelect option: ");
        try {
            std::string line = console_.read_line();
            if (!line.empty()) {
                int choice = std::stoi(line);
                if (choice == 1) return MainMenuOption::AnalyzeRelease;
                if (choice == 2) return MainMenuOption::AnalyzeDebug;
                if (choice == 3) return MainMenuOption::Exit;
            }
        } catch (...) {}
        return MainMenuOption::Invalid;
    }

    std::optional<fs::path> ConsoleUI::selectFile(const std::string& title, const std::vector<fs::path>& items) const {
        const size_t itemsPerPage = 3;
        std::vector<fs::path> filteredItems = items;
        size_t currentPage = 0;
        std::string searchTerm;
        while (true) {
            console_.clear();
            console_.write(title + "\n");
            if (!searchTerm.empty()) console_.write("Search: \"" + searchTerm + "\"\n");
            console_.write("--------------------------------------------------------\n");
            size_t totalPages = (filteredItems.empty()) ? 1 : (filteredItems.size() + itemsPerPage - 1) / itemsPerPage;
            if (currentPage >= totalPages && totalPages > 0) currentPage = totalPages - 1;
            size_t startIndex = currentPage * itemsPerPage;
            size_t endIndex = (std::min)(startIndex + itemsPerPage, filteredItems.size());
            if (filteredItems.empty()) console_.write("Nothing found.\n");
            else for (size_t i = startIndex; i < endIndex; ++i) console_.write("[" + std::to_string(i - startIndex + 1) + "] " + filteredItems[i].filename().string() + "\n");
            console_.write("\n--- Page " + std::to_string(filteredItems.empty() ? 0 : currentPage + 1) + " of " + std::to_string(totalPages) + " ---\n");
            console_.write("Navigate: [<-][->] | [s]earch | [c]lear | [q]uit | Enter to select: ");
            std::string current_input;
            while (true) {
                Platform::KeyPress press = console_.get_key_press();
                if (press.key == Platform::KeyPress::Enter) {
                    try {
                        if (current_input.empty()) continue;
                        size_t actual_index = startIndex + std::stoul(current_input) - 1;
                        if (actual_index < endIndex) {
                            console_.write("\n");
                            return filteredItems[actual_index];
                        }
                    } catch (...) {}
                    current_input.clear();
                    console_.write("\nInvalid. Try again: ");
                } else if (press.key == Platform::KeyPress::Left) {
                    if (currentPage > 0) { currentPage--; break; }
                } else if (press.key == Platform::KeyPress::Right) {
                    if (currentPage + 1 < totalPages) { currentPage++; break; }
                } else if (press.key == Platform::KeyPress::Backspace) {
                    if (!current_input.empty()) { current_input.pop_back(); console_.write("\b \b"); }
                } else if (press.key == Platform::KeyPress::Char) {
                    if (press.value == 'q') { return std::nullopt; }
                    if (press.value == 's') {
                        console_.write("s\nSearch term: ");
                        searchTerm = console_.read_line();
                        filteredItems.clear();
                        std::string lowerSearchTerm = searchTerm;
                        std::transform(lowerSearchTerm.begin(), lowerSearchTerm.end(), lowerSearchTerm.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                        for(const auto& item : items) {
                            std::string filename = item.filename().string();
                            std::transform(filename.begin(), filename.end(), filename.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                            if (filename.find(lowerSearchTerm) != std::string::npos) filteredItems.push_back(item);
                        }
                        currentPage = 0;
                        break;
                    }
                    if (press.value == 'c') {
                        console_.write("c\n"); searchTerm = ""; filteredItems = items; currentPage = 0; break;
                    }
                    if (std::isdigit(static_cast<unsigned char>(press.value))) {
                        current_input += press.value;
                        console_.write(std::string(1, press.value));
                    }
                }
            }
        }
    }

    std::optional<fs::path> ConsoleUI::promptForManualPath() const {
        console_.clear();
        console_.write("Bugreport files not found.\n1) Enter path manually\n2) Return to menu\nSelect option: ");
        if (console_.read_line() == "1") {
            console_.write("Enter full path: ");
            return console_.read_line();
        }
        return std::nullopt;
    }

    void ConsoleUI::showMessage(const std::string& msg, bool pause) const {
        console_.write(msg + "\n");
        if (pause) {
            console_.write("\nPress any key to continue...");
            console_.get_key_press();
        }
    }

    void ConsoleUI::displayResults(const Core::ReportData& data, bool isDebug) const {
        console_.clear();
        std::string logFilename = data.getLogFilename();
        std::ofstream logFile(logFilename);
        if (!logFile) throw std::runtime_error("Failed to open log file: " + logFilename);

        auto printAndLog = [&](const std::string& text) {
            std::cout << text << std::endl;
            logFile << text << std::endl;
        };

        printAndLog("--- General Information ---");
        printAndLog("Model: " + (data.model.empty() ? "N/A" : data.model));
        printAndLog("Android Version: " + (data.androidVersion.empty() ? "N/A" : data.androidVersion));
        if(!data.magiskVersion.empty()) printAndLog("Magisk Version: " + data.magiskVersion);
        printAndLog("Серийный номер: " + (data.serialNumber.empty() ? "N/A" : data.serialNumber));
        printAndLog("Bootloader: " + (data.bootloaderStatus.empty() ? "N/A" : data.bootloaderStatus));
        printAndLog("SELinux Status: " + data.seLinuxStatus);
        printAndLog("Build Fingerprint: " + (data.buildFingerprint.empty() ? "N/A" : data.buildFingerprint));
        printAndLog("\n--- Analysis Results ---");

        printAndLog("\nFinal Score: " + std::to_string(data.totalScore) + "/10");
        if (data.totalScore == 0) printAndLog("Verdict:  This device is clean,no signs of rooting or modification were found,Have fun :D");
        else if (data.totalScore >= 1 && data.totalScore <= 4) printAndLog("Verdict: Suspicious. Some weak or ambiguous indicators were found.");
        else printAndLog("Verdict: Critical. High-confidence evidence of system modification was detected.");

        static const std::map<Core::DetectionCategory, std::string> CATEGORY_NAMES = {
            {Core::DetectionCategory::RootAndFrameworks, "Root & Frameworks"}, {Core::DetectionCategory::RootHidingAndEvasion, "Root Hiding & Evasion"},
            {Core::DetectionCategory::ProhibitedPackages, "Prohibited Packages"}, {Core::DetectionCategory::Anomalies, "Behavioral Anomalies"},
            {Core::DetectionCategory::FileSystemAndMounts, "File System & Mounts"}, {Core::DetectionCategory::AnomalousLogs, "Anomalous System Logs"},
            {Core::DetectionCategory::SuspiciousProperties, "Suspicious Properties"}, {Core::DetectionCategory::CustomBuild, "Custom Build"},
            {Core::DetectionCategory::AppAnalysis, "Application Analysis"}
        };

        for (const auto& [category, name] : CATEGORY_NAMES) {
            auto it = data.detections.find(category);
            bool detected = (it != data.detections.end() && !it->second.empty());
            printAndLog("\n[" + name + "]: " + (detected ? "Detected" : "Undetected"));
            if (detected) {
                for (const auto& item : it->second) {
                    printAndLog("- " + item);
                }
            }
        }

        if (isDebug && !data.debugLog.empty()) {
            logFile << "\n\n--- Debug Log ---\n";
            for (const auto& log_line : data.debugLog) {
                logFile << log_line << "\n";
            }
            std::cout << "\n(A detailed debug log has been written to the file)" << std::endl;
        }

        std::cout << "\nResults saved to: " + logFilename << std::endl;
    }
}
