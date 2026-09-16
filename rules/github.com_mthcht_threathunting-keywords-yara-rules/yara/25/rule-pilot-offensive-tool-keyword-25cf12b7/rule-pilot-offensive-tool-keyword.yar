rule rule_PILOT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PILOT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PILOT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PILOT_offensive_tool_keyword = /\#\sAuthor\:\sDahvid\sSchloss\sa\.k\.a\sAPT\sBig\sDaddy/ nocase ascii wide
                        $string2_PILOT_offensive_tool_keyword = /\/PILOT\/ATC\.py/ nocase ascii wide
                        $string3_PILOT_offensive_tool_keyword = /\/PILOT\/PILOT\.ps1/ nocase ascii wide
                        $string4_PILOT_offensive_tool_keyword = /\\PILOT\.ps1/ nocase ascii wide
                        $string5_PILOT_offensive_tool_keyword = /\\PILOT\\ATC\.py/ nocase ascii wide
                        $string6_PILOT_offensive_tool_keyword = "4870b4163315fa666dea8be03176d76aa215fe33187db45aca984e07b25ca827" nocase ascii wide
                        $string7_PILOT_offensive_tool_keyword = "810950f1d775ffa916c75a85c79bb2a46f7c7250986be7748bfae90b04b33551" nocase ascii wide
                        $string8_PILOT_offensive_tool_keyword = "Create a raw socket to listen for ICMP packets cause f scappy we don't need that shit" nocase ascii wide
                        $string9_PILOT_offensive_tool_keyword = /dahvid\.schloss\@echeloncyber\.com/ nocase ascii wide
                        $string10_PILOT_offensive_tool_keyword = "dahvidschloss/PILOT" nocase ascii wide
                        $string11_PILOT_offensive_tool_keyword = /Listening\sfor\sincoming\sICMP\spackets\.\.\./ nocase ascii wide
                        $string12_PILOT_offensive_tool_keyword = "run-pilot -targetIP " nocase ascii wide
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