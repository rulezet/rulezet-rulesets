rule ShadowHound
{
    meta:
        description = "Detection patterns for the tool 'ShadowHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbofhound\.py/ nocase ascii wide
                        $string2 = /\/bofhound\.py/ nocase ascii wide
                        $string3 = /\/ShadowHound\.git/ nocase ascii wide
                        $string4 = /\\bofhound\.py/ nocase ascii wide
                        $string5 = "a510e14853234b49b9053a18264aa29e4dfbf467edae47afe13a08d57d34dad4" nocase ascii wide
                        $string6 = /Author\:\sYehuda\sSmirnov\s\(X\:\s\@yudasm_\sBlueSky\:\s\@yudasm\.bsky\.social\)/ nocase ascii wide
                        $string7 = "b7ae4b58d31453da02817000dd7465ab68434f43e22d2b7a5ffc73f3fa65f6cd" nocase ascii wide
                        $string8 = "Friends-Security/ShadowHound" nocase ascii wide
                        $string9 = "shadowhound -Command " nocase ascii wide
                        $string10 = "ShadowHound-ADM " nocase ascii wide
                        $string11 = /ShadowHound\-ADM\.ps1/ nocase ascii wide
                        $string12 = "ShadowHound-DS " nocase ascii wide
                        $string13 = /ShadowHound\-DS\(/ nocase ascii wide
                        $string14 = /ShadowHound\-DS\.ps1/ nocase ascii wide
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