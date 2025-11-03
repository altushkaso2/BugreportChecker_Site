#include "Application.h"
#include "miniz.h"

Application::Application() 
    : console_(Platform::create_console()), 
      ui_(*console_) 
{
    cleanupTempDirs();
}

Application::~Application() {
    cleanupTempDirs();
}

void Application::cleanupTempDirs() const {
    std::error_code ec;
    if (fs::exists(TEMP_EXTRACT_DIR)) {
        fs::remove_all(TEMP_EXTRACT_DIR, ec);
    }
    if (fs::exists(TEMP_FINAL_DIR)) {
        fs::remove_all(TEMP_FINAL_DIR, ec);
    }
}

bool Application::extractZip(const fs::path& zipPath, const fs::path& extractToDir) const {
    mz_zip_archive zip_archive = {};
    if (!mz_zip_reader_init_file(&zip_archive, zipPath.string().c_str(), 0)) {
        return false;
    }

    fs::create_directories(extractToDir);

    for (mz_uint i = 0; i < mz_zip_reader_get_num_files(&zip_archive); ++i) {
        mz_zip_archive_file_stat file_stat;
        if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat)) {
            continue;
        }

        fs::path dest_path = extractToDir / fs::path(file_stat.m_filename).relative_path();

        if (mz_zip_reader_is_file_a_directory(&zip_archive, i)) {
            fs::create_directories(dest_path);
        } else {
            fs::create_directories(dest_path.parent_path());
            if (!mz_zip_reader_extract_to_file(&zip_archive, i, dest_path.string().c_str(), 0)) {
            }
        }
    }

    mz_zip_reader_end(&zip_archive);
    return true;
}

std::vector<fs::path> Application::findBugReports() const {
    ui_.showMessage("Searching for bugreport files (*.zip, *.txt)...");
    std::set<fs::path> found_files_set;
    std::vector<fs::path> search_paths;
    
#ifdef _WIN32
    const char* home_path_cstr = getenv("USERPROFILE");
#else
    const char* home_path_cstr = getenv("HOME");
#endif
    
    if (home_path_cstr) {
        fs::path home_path(home_path_cstr);
        if (fs::exists(home_path)) search_paths.push_back(home_path);
        if (fs::exists(home_path / "Desktop")) search_paths.push_back(home_path / "Desktop");
        if (fs::exists(home_path / "Downloads")) search_paths.push_back(home_path / "Downloads");
        if (fs::exists(home_path / "storage/downloads")) search_paths.push_back(home_path / "storage/downloads");
    }
    
    search_paths.push_back(fs::current_path());
    
    for (const auto& path : search_paths) {
        try {
            if (!fs::exists(path) || !fs::is_directory(path)) continue;
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    std::string lower_filename = entry.path().filename().string();
                    std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                    
                    if (lower_filename.rfind("bugreport", 0) == 0 && (lower_filename.find(".zip") != std::string::npos || lower_filename.find(".txt") != std::string::npos)) {
                        found_files_set.insert(entry.path());
                    }
                }
            }
        } catch(const fs::filesystem_error&){}
    }
    
    std::vector<fs::path> found_files(found_files_set.begin(), found_files_set.end());
    std::sort(found_files.begin(), found_files.end(), [](const fs::path& a, const fs::path& b) {
        try { return fs::last_write_time(a) > fs::last_write_time(b); } catch (...) { return false; }
    });
    
    return found_files;
}

void Application::handleAnalysis(bool isDebug, std::optional<fs::path> initial_path) {
    console_->clear();
    std::optional<fs::path> selected_path_opt = initial_path;
    
    if (!selected_path_opt) {
        auto found_files = findBugReports();
        if (found_files.empty()) {
            selected_path_opt = ui_.promptForManualPath();
        } else {
            selected_path_opt = ui_.selectFile("Found files (newest first):", found_files);
        }
    }

    if (!selected_path_opt) {
        return;
    }
    
    cleanupTempDirs();
    fs::path final_report_dir;
    fs::path original_report_path = *selected_path_opt;
    std::string ext = original_report_path.extension().string();

    try {
        if (ext == ".txt") {
            std::cout << "Copying report to temporary directory...\n";
            fs::create_directory(TEMP_FINAL_DIR);
            fs::copy_file(original_report_path, TEMP_FINAL_DIR / original_report_path.filename());
            final_report_dir = TEMP_FINAL_DIR;
        } else if (ext == ".zip") {
            std::cout << "Extracting main bugreport zip...\n";
            if (!extractZip(original_report_path, TEMP_EXTRACT_DIR)) {
                throw std::runtime_error("Failed to extract main zip file.");
            }

            fs::path inner_zip_path;
            for (const auto& entry : fs::directory_iterator(TEMP_EXTRACT_DIR)) {
                std::string lower_filename = entry.path().filename().string();
                std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                if (entry.is_regular_file() && lower_filename.rfind("bugreport", 0) == 0 && lower_filename.find(".zip") != std::string::npos) {
                    inner_zip_path = entry.path();
                    break;
                }
            }

            if (inner_zip_path.empty()) {
                throw std::runtime_error("Could not find inner bugreport zip file.");
            }

            std::cout << "Extracting inner report data (with FS folder)...\n";
            if (!extractZip(inner_zip_path, TEMP_FINAL_DIR)) {
                throw std::runtime_error("Failed to extract inner zip file.");
            }
            final_report_dir = TEMP_FINAL_DIR;
        } else {
            throw std::runtime_error("Unsupported file type: " + ext);
        }

        Core::ReportData data;
        auto progress_bar = [this](float progress) {
            int bar_width = 50;
            std::cout << "\rAnalyzing [";
            int pos = (int)(bar_width * (progress / 100.0));
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cout << "#";
                else if (i == pos) std::cout << "#";
                else std::cout << ".";
            }
            std::cout << "] " << std::fixed << std::setprecision(1) << progress << "% " << std::flush;
        };

        std::cout << "Analyzing '" + original_report_path.string() + "'...\n";
        analyzer_.analyze(final_report_dir, progress_bar, data);
        std::cout << std::endl;
        ui_.displayResults(data, isDebug);

    } catch (const std::exception& e) {
        std::cout << std::endl;
        ui_.showMessage("Critical error: " + std::string(e.what()));
    }
    
    cleanupTempDirs();
    ui_.showMessage("", true);
}


void Application::run(int argc, char* argv[]) {
    if (argc > 1) {
        fs::path initial_path = argv[1];
        if (fs::exists(initial_path)) {
            bool isDebug = (argc > 2 && std::string(argv[2]) == "--debug");
            handleAnalysis(isDebug, initial_path);
        } else {
            ui_.showMessage("File not found: " + std::string(argv[1]), true);
        }
        return;
    }

    while(true) {
        auto choice = ui_.displayMainMenu();
        if (choice == UI::ConsoleUI::MainMenuOption::AnalyzeRelease) {
            handleAnalysis(false);
        } else if (choice == UI::ConsoleUI::MainMenuOption::AnalyzeDebug) {
            handleAnalysis(true);
        }
        else if (choice == UI::ConsoleUI::MainMenuOption::Exit) {
            console_->clear();
            ui_.showMessage("DebugReport Checker by altushkaso2. Exiting.");
            break;
        }
        else {
            ui_.showMessage("Invalid input.", true);
        }
    }
}
