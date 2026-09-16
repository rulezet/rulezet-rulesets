rule rule_Box_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Box"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Box_greyware_tool_keyword = /\.realtime\.services\.box\.net/ nocase ascii wide
                        $string2_Box_greyware_tool_keyword = /\/BoxDrive\.msi/ nocase ascii wide
                        $string3_Box_greyware_tool_keyword = /\\\.boxcanvas\\BoxDesktop/ nocase ascii wide
                        $string4_Box_greyware_tool_keyword = /\\box\.desktop\.updateservice\.exe/ nocase ascii wide
                        $string5_Box_greyware_tool_keyword = /\\Box\.Updater\.Common\.dll/ nocase ascii wide
                        $string6_Box_greyware_tool_keyword = /\\box\\box\.exe/ nocase ascii wide
                        $string7_Box_greyware_tool_keyword = /\\Box\\ui\\BoxUI\.exe/ nocase ascii wide
                        $string8_Box_greyware_tool_keyword = /\\BoxDesktop\.boxnote\\shell\\/ nocase ascii wide
                        $string9_Box_greyware_tool_keyword = /\\BoxDrive\.msi/ nocase ascii wide
                        $string10_Box_greyware_tool_keyword = /\\Program\sFiles\\Box\\Box\\/ nocase ascii wide
                        $string11_Box_greyware_tool_keyword = /\\Root\\InventoryApplicationFile\\boxui\.exe/ nocase ascii wide
                        $string12_Box_greyware_tool_keyword = /\>Box\,\sInc\.\</ nocase ascii wide
                        $string13_Box_greyware_tool_keyword = /Box\.Desktop\.Installer\.CustomActions/ nocase ascii wide
                        $string14_Box_greyware_tool_keyword = /cdn.{0,100}\.boxcdn\.net/ nocase ascii wide
                        $string15_Box_greyware_tool_keyword = /HKLM\\SOFTWARE\\Box\\Box/ nocase ascii wide
                        $string16_Box_greyware_tool_keyword = /sanalytics\.box\.com/ nocase ascii wide
                        $string17_Box_greyware_tool_keyword = /upload\.box\.com/ nocase ascii wide
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