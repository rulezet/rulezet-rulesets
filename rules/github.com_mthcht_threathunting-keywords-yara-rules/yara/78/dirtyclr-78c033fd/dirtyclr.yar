rule DirtyCLR
{
    meta:
        description = "Detection patterns for the tool 'DirtyCLR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirtyCLR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DirtyCLR\.git/ nocase ascii wide
                        $string2 = /\\DirtyCLR\.sln/ nocase ascii wide
                        $string3 = /\\DirtyCLR\-main/ nocase ascii wide
                        $string4 = ">DirtyCLR<" nocase ascii wide
                        $string5 = "46EB7B83-3404-4DFC-94CC-704B02D11464" nocase ascii wide
                        $string6 = "827310760fa3d7371a22ff5f06e406f3e0a6cbe1c7e7f38244e0334a2d5eca7d" nocase ascii wide
                        $string7 = "8e2f8144fae305ecff5759bb38e384682642e766dfe85179555d7b621d92b836" nocase ascii wide
                        $string8 = "dirtyclrdomain" nocase ascii wide
                        $string9 = "ipSlav/DirtyCLR" nocase ascii wide
                        $string10 = /key.{0,100}kda47y298uned/ nocase ascii wide
                        $string11 = /sn\.exe\s\-k\skey\.snk/ nocase ascii wide
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