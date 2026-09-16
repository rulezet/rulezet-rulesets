rule crossc2
{
    meta:
        description = "Detection patterns for the tool 'crossc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crossc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/CrossC2-test" nocase ascii wide
                        $string2 = "/mimipenguin/" nocase ascii wide
                        $string3 = /\/tmp\/c2\-rebind\.so/
                        $string4 = /c2profile\.profile/ nocase ascii wide
                        $string5 = "cc2_keystrokes" nocase ascii wide
                        $string6 = "cc2_portscan" nocase ascii wide
                        $string7 = /CCHOST\=127\.0\.0\.1.{0,100}\/tmp\/c2/ nocase ascii wide
                        $string8 = "crossc2 dyn load" nocase ascii wide
                        $string9 = "CrossC2 framework" nocase ascii wide
                        $string10 = /CrossC2\.cna/ nocase ascii wide
                        $string11 = /CrossC2\.git/ nocase ascii wide
                        $string12 = /CrossC2\.Linux/
                        $string13 = /CrossC2\.MacOS/ nocase ascii wide
                        $string14 = /CrossC2\.Win/ nocase ascii wide
                        $string15 = "CrossC2_dev_" nocase ascii wide
                        $string16 = "CrossC2-cs" nocase ascii wide
                        $string17 = "CrossC2-GithubBot" nocase ascii wide
                        $string18 = "CrossC2Kit" nocase ascii wide
                        $string19 = "genCrossC2 " nocase ascii wide
                        $string20 = /genCrossC2\.Win\.exe/ nocase ascii wide
                        $string21 = "gloxec/CrossC2" nocase ascii wide
                        $string22 = /http\:\/\/127\.0\.0\.1\/CrossC2/ nocase ascii wide
                        $string23 = /http\:\/\/127\.0\.0\.1\:443\/aaaaaaaaa/ nocase ascii wide
                        $string24 = /http\:\/\/127\.0\.0\.1\:443\/bbbbbbbbb/ nocase ascii wide
                        $string25 = /mimipenguin\./ nocase ascii wide
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