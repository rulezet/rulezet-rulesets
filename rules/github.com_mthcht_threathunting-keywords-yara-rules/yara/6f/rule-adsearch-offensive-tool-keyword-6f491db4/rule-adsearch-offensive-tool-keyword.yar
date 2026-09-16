rule rule_adsearch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adsearch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=computer\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=524288\)\)/ nocase ascii wide
                        $string2_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=.{0,100}Admins/ nocase ascii wide
                        $string3_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=group\)\(cn\=MS\sSQL\sAdmins\)/ nocase ascii wide
                        $string4_adsearch_offensive_tool_keyword = /\s\-\-search\s\\"\(\&\(objectCategory\=user\)\(userAccountControl\:1\.2\.840\.113556\.1\.4\.803\:\=4194304\)\)/ nocase ascii wide
                        $string5_adsearch_offensive_tool_keyword = /\/ADSearch\.git/ nocase ascii wide
                        $string6_adsearch_offensive_tool_keyword = /adsearch.{0,100}\s\-\-domain\-admins/ nocase ascii wide
                        $string7_adsearch_offensive_tool_keyword = /adsearch\.exe/ nocase ascii wide
                        $string8_adsearch_offensive_tool_keyword = /ADSearch\.sln/ nocase ascii wide
                        $string9_adsearch_offensive_tool_keyword = /ADSearch\\ADSearch\.cs/ nocase ascii wide
                        $string10_adsearch_offensive_tool_keyword = /adsearch\-master\.zip/ nocase ascii wide
                        $string11_adsearch_offensive_tool_keyword = "tomcarver16/ADSearch" nocase ascii wide
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