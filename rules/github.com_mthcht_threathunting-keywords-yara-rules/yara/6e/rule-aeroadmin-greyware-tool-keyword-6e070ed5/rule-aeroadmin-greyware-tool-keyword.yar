rule rule_aeroadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'aeroadmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aeroadmin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_aeroadmin_greyware_tool_keyword = /\saeroadmin\.exe/ nocase ascii wide
                        $string2_aeroadmin_greyware_tool_keyword = /\/aeroadmin\.exe/ nocase ascii wide
                        $string3_aeroadmin_greyware_tool_keyword = /\\AeroAdmin\s.{0,100}_Portable\.exe/ nocase ascii wide
                        $string4_aeroadmin_greyware_tool_keyword = /\\aeroadmin\.exe/ nocase ascii wide
                        $string5_aeroadmin_greyware_tool_keyword = /\\Aeroadmin\.lnk/ nocase ascii wide
                        $string6_aeroadmin_greyware_tool_keyword = /\\Aeroadmin\\black\.bmp/ nocase ascii wide
                        $string7_aeroadmin_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AeroadminService/ nocase ascii wide
                        $string8_aeroadmin_greyware_tool_keyword = /\\CurrentControlSet\\Services\\AeroadminService/ nocase ascii wide
                        $string9_aeroadmin_greyware_tool_keyword = /\\InventoryApplicationFile\\aeroadmin/ nocase ascii wide
                        $string10_aeroadmin_greyware_tool_keyword = /\\ProgramData\\Aeroadmin\\/ nocase ascii wide
                        $string11_aeroadmin_greyware_tool_keyword = "2ef8a13faa44755fab1ac6fb3665cc78f7e7b451" nocase ascii wide
                        $string12_aeroadmin_greyware_tool_keyword = "Aeroadmin LLC" nocase ascii wide
                        $string13_aeroadmin_greyware_tool_keyword = /AeroAdmin\sPRO\s\-\sremote\sdesktop\.exe/ nocase ascii wide
                        $string14_aeroadmin_greyware_tool_keyword = /AeroAdmin\sPRO\.exe/ nocase ascii wide
                        $string15_aeroadmin_greyware_tool_keyword = /AeroAdmin\sv4\..{0,100}\s\(/ nocase ascii wide
                        $string16_aeroadmin_greyware_tool_keyword = /AeroAdmin\.cpp/ nocase ascii wide
                        $string17_aeroadmin_greyware_tool_keyword = /AEROADMIN\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string18_aeroadmin_greyware_tool_keyword = /Aeroadmin\\Screenshots/ nocase ascii wide
                        $string19_aeroadmin_greyware_tool_keyword = /AeroAdmin_2\.exe/ nocase ascii wide
                        $string20_aeroadmin_greyware_tool_keyword = "AeroadminService" nocase ascii wide
                        $string21_aeroadmin_greyware_tool_keyword = /auth.{0,100}\.aeroadmin\.com/ nocase ascii wide
                        $string22_aeroadmin_greyware_tool_keyword = /auth11\.aeroadmin\.com/ nocase ascii wide
                        $string23_aeroadmin_greyware_tool_keyword = /DEFAULT\\Software\\AeroAdmin/ nocase ascii wide
                        $string24_aeroadmin_greyware_tool_keyword = "EE54577067550559C4711C9E5E10435807F9DEEE9A5ADB4409CB60A6B0108700" nocase ascii wide
                        $string25_aeroadmin_greyware_tool_keyword = /ulm\.aeroadmin\.com\// nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}