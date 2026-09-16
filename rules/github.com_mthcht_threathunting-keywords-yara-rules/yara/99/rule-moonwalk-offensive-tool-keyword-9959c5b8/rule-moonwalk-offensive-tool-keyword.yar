rule rule_moonwalk_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'moonwalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "moonwalk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_moonwalk_offensive_tool_keyword = " -o moonwalk"
                        $string2_moonwalk_offensive_tool_keyword = /\/\.MOONWALK/
                        $string3_moonwalk_offensive_tool_keyword = /\/log_file_timestamps\.json/
                        $string4_moonwalk_offensive_tool_keyword = /\/moonwalk\.git/
                        $string5_moonwalk_offensive_tool_keyword = "/moonwalk_darwin"
                        $string6_moonwalk_offensive_tool_keyword = /\/v1\.0\.0\/moonwalk_linux/
                        $string7_moonwalk_offensive_tool_keyword = "4c368fe58781e363b1176be2a6efcfaaa74432309d1cfc251174a5650debfbe8"
                        $string8_moonwalk_offensive_tool_keyword = "62a69abb559cbca8163cb933445bce62a2e73f5dffcf2a77e28f8f64fc1889fd"
                        $string9_moonwalk_offensive_tool_keyword = "90873c2ac02c860b3b6ec7cf262ab58504ff187dd9e638bbabef94e985607836"
                        $string10_moonwalk_offensive_tool_keyword = /clear_me_from_history\(\)\?/
                        $string11_moonwalk_offensive_tool_keyword = "Finish moonwalk and clear your traces"
                        $string12_moonwalk_offensive_tool_keyword = "moonwalk finish"
                        $string13_moonwalk_offensive_tool_keyword = /moonwalk\sget\s.{0,100}history/
                        $string14_moonwalk_offensive_tool_keyword = "moonwalk start"
                        $string15_moonwalk_offensive_tool_keyword = "mufeedvh/moonwalk"
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}