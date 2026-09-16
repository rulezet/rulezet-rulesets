rule deimosc2
{
    meta:
        description = "Detection patterns for the tool 'deimosc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "deimosc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/collection/screengrab" nocase ascii wide
                        $string2 = /\/dlls\/c2\.c/ nocase ascii wide
                        $string3 = "/gosecretsdump" nocase ascii wide
                        $string4 = "/resources/selfdestruction" nocase ascii wide
                        $string5 = "/shellinject" nocase ascii wide
                        $string6 = /\/webshells\/shell\.aspx/ nocase ascii wide
                        $string7 = /\/webshells\/shell\.php/ nocase ascii wide
                        $string8 = /\\gosecretsdump/ nocase ascii wide
                        $string9 = "00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64" nocase ascii wide
                        $string10 = "04ca7e137e1e9feead96a7df45bb67d5ab3de190" nocase ascii wide
                        $string11 = "38ea755e162c55ef70f9506dddfd01641fc838926af9c43eda652da63c67058b" nocase ascii wide
                        $string12 = "DeimosC2" nocase ascii wide
                        $string13 = /lsadump\.exe/ nocase ascii wide
                        $string14 = /minidump\.exe/ nocase ascii wide
                        $string15 = "module inject " nocase ascii wide
                        $string16 = /ntdsdump\.exe/ nocase ascii wide
                        $string17 = /samdump\.exe/ nocase ascii wide
                        $string18 = /samdump\.py/ nocase ascii wide
                        $string19 = /screengrab\.exe/ nocase ascii wide
                        $string20 = /shadowdump\./ nocase ascii wide
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