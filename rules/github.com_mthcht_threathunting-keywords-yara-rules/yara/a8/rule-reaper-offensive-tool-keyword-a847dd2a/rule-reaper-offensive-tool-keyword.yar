rule rule_reaper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reaper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reaper_offensive_tool_keyword = /\/Reaper\.git/ nocase ascii wide
                        $string2_reaper_offensive_tool_keyword = /\/Reaper\/Reaper\.cpp/ nocase ascii wide
                        $string3_reaper_offensive_tool_keyword = /\/ReaperX64\.zip/ nocase ascii wide
                        $string4_reaper_offensive_tool_keyword = /\\Reaper\\Reaper\.cpp/ nocase ascii wide
                        $string5_reaper_offensive_tool_keyword = /\\Reaper\-main\\.{0,100}\.sys/ nocase ascii wide
                        $string6_reaper_offensive_tool_keyword = /\\Temp\\Reaper\.exe/ nocase ascii wide
                        $string7_reaper_offensive_tool_keyword = "30f7ba049eab00673ae6b247199ec4f6af533d9ba46482159668fd23f484bdc6" nocase ascii wide
                        $string8_reaper_offensive_tool_keyword = "526f652d4d9e20a19374817eac75b914b75f3bfaecc16b65f979e5758ea62476" nocase ascii wide
                        $string9_reaper_offensive_tool_keyword = "c725919e6357126d512c638f993cf572112f323da359645e4088f789eb4c7b8c" nocase ascii wide
                        $string10_reaper_offensive_tool_keyword = "CB561720-0175-49D9-A114-FE3489C53661" nocase ascii wide
                        $string11_reaper_offensive_tool_keyword = /github\.com\/.{0,100}Reaper\.exe/ nocase ascii wide
                        $string12_reaper_offensive_tool_keyword = "MrEmpy/Reaper" nocase ascii wide
                        $string13_reaper_offensive_tool_keyword = /Reaper\.exe\skp\s/ nocase ascii wide
                        $string14_reaper_offensive_tool_keyword = /Reaper\.exe\ssp\s/ nocase ascii wide
                        $string15_reaper_offensive_tool_keyword = /Reaper\-main\.zip/ nocase ascii wide
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