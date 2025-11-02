#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <limits>
#include <functional>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <optional>
#include <cstdlib>
#include <cctype>
#include <sstream>
#include <regex>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <unistd.h>
#include <termios.h>
#endif

namespace fs = std::filesystem;
