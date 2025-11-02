#include "rules/Rules.h"

namespace Core {
    namespace Rules {

        void parse_property_line(std::string_view line, std::string_view& out_key, std::string_view& out_value) {
            if (line.empty() || line.front() != '[') return;
            auto key_end = line.find("]:");
            if (key_end == std::string_view::npos) return;
            out_key = line.substr(1, key_end - 1);
            std::string_view value_part = line.substr(key_end + 2);
            value_part.remove_prefix((std::min)(value_part.find_first_not_of(" \t"), value_part.size()));
            if (value_part.length() >= 2 && value_part.front() == '[' && value_part.back() == ']') {
                out_value = value_part.substr(1, value_part.length() - 2);
            } else {
                out_value = value_part;
            }
        }

    }
}
