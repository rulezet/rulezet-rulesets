rule DataBouncing
{
    meta:
        description = "Detection patterns for the tool 'DataBouncing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DataBouncing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdeadPool\.ps1/ nocase ascii wide
                        $string2 = /\sexfilGui\.ps1/ nocase ascii wide
                        $string3 = /\snightCrawler\.ps1/ nocase ascii wide
                        $string4 = /\swget\s\\"https\:\/\/.{0,100}\/interactshbuild/ nocase ascii wide
                        $string5 = /\/DataBouncing\.git/ nocase ascii wide
                        $string6 = /\/deadPool\.ps1/ nocase ascii wide
                        $string7 = /\/exfilGui\.ps1/ nocase ascii wide
                        $string8 = /\/nightCrawler\.ps1/ nocase ascii wide
                        $string9 = /\\deadPool\.ps1/ nocase ascii wide
                        $string10 = /\\exfilGui\.ps1/ nocase ascii wide
                        $string11 = /\\nightCrawler\.ps1/ nocase ascii wide
                        $string12 = /bash\s\.\/bounce\.sh/
                        $string13 = /clndh3qilvdv6403g1n0hs3rhd6xpfmjn\.oast\.online/ nocase ascii wide
                        $string14 = /DataBouncing\-main\.zip/ nocase ascii wide
                        $string15 = /exfil\s\-regex.{0,100}\s\-domain.{0,100}\-url\s.{0,100}\s\-filepath\s/ nocase ascii wide
                        $string16 = /Find\-Secret\s\-FilePath\s\.\/logs\.txt\s\-Regex\s/
                        $string17 = /https\:\/\/unit259\.fyi\/db/ nocase ascii wide
                        $string18 = /irm\sunit259\.fyi\/dbgui\s\|\siex/ nocase ascii wide
                        $string19 = /nightCrawler\.ps1\s/ nocase ascii wide
                        $string20 = "Unit-259/DataBouncing" nocase ascii wide
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