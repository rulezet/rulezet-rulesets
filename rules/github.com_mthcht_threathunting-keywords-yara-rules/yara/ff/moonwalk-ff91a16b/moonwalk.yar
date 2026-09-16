rule moonwalk
{
    meta:
        description = "Detection patterns for the tool 'moonwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "moonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -o moonwalk"
                        $string2 = /\/\.MOONWALK/
                        $string3 = /\/log_file_timestamps\.json/
                        $string4 = /\/moonwalk\.git/
                        $string5 = "/moonwalk_darwin"
                        $string6 = /\/v1\.0\.0\/moonwalk_linux/
                        $string7 = "4c368fe58781e363b1176be2a6efcfaaa74432309d1cfc251174a5650debfbe8"
                        $string8 = "62a69abb559cbca8163cb933445bce62a2e73f5dffcf2a77e28f8f64fc1889fd"
                        $string9 = "90873c2ac02c860b3b6ec7cf262ab58504ff187dd9e638bbabef94e985607836"
                        $string10 = /clear_me_from_history\(\)\?/
                        $string11 = "Finish moonwalk and clear your traces"
                        $string12 = "moonwalk finish"
                        $string13 = /moonwalk\sget\s.{0,1000}history/
                        $string14 = "moonwalk start"
                        $string15 = "mufeedvh/moonwalk"

    condition:
        any of them
}