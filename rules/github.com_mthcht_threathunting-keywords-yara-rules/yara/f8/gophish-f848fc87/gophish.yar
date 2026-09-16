rule gophish
{
    meta:
        description = "Detection patterns for the tool 'gophish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gophish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " evilginx" nocase ascii wide
                        $string2 = "/evilginx" nocase ascii wide
                        $string3 = /\/gophish\.db/ nocase ascii wide
                        $string4 = "/gophish/" nocase ascii wide
                        $string5 = "c121f7d62fa5ecd27c3aaae5737a3de8f2e4def0c182058b6dd824aa92351e9c" nocase ascii wide
                        $string6 = /evilfeed\.go/ nocase ascii wide
                        $string7 = "evilginx-linux"
                        $string8 = "evilgophish" nocase ascii wide
                        $string9 = /gophish.{0,100}phish\.go/ nocase ascii wide
                        $string10 = /gophish\.go/ nocase ascii wide
                        $string11 = "gophish/gophish" nocase ascii wide
                        $string12 = "localhost:1337" nocase ascii wide
                        $string13 = "lures create " nocase ascii wide
                        $string14 = /phish_test\.go/ nocase ascii wide
                        $string15 = "phishlets " nocase ascii wide
                        $string16 = "sneaky_gophish" nocase ascii wide
                        $string17 = "X-Gophish-Contact" nocase ascii wide
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