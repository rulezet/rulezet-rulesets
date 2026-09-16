rule rule_ffuf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ffuf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ffuf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ffuf_offensive_tool_keyword = /\s\-o\sffuf\.csv/
                        $string2_ffuf_offensive_tool_keyword = /\/ffuf\.git/
                        $string3_ffuf_offensive_tool_keyword = "/ffuf/ffufrc"
                        $string4_ffuf_offensive_tool_keyword = "cd ffuf"
                        $string5_ffuf_offensive_tool_keyword = /ffuf\s.{0,100}\-input\-cmd/
                        $string6_ffuf_offensive_tool_keyword = /ffuf\s.{0,100}\-u\shttp/
                        $string7_ffuf_offensive_tool_keyword = "ffuf -c "
                        $string8_ffuf_offensive_tool_keyword = "ffuf -w "
                        $string9_ffuf_offensive_tool_keyword = /ffuf\.exe/
                        $string10_ffuf_offensive_tool_keyword = "ffuf/ffuf"
                        $string11_ffuf_offensive_tool_keyword = /ffuf_.{0,100}_freebsd_.{0,100}\.tar\.gz/
                        $string12_ffuf_offensive_tool_keyword = /ffuf_.{0,100}_linux_.{0,100}\.tar\.gz/
                        $string13_ffuf_offensive_tool_keyword = /ffuf_.{0,100}_macOS_.{0,100}\.tar\.gz/
                        $string14_ffuf_offensive_tool_keyword = /ffuf_.{0,100}_openbsd_.{0,100}\.tar\.gz/
                        $string15_ffuf_offensive_tool_keyword = /ffuf_.{0,100}_windows_.{0,100}\.zip/
                        $string16_ffuf_offensive_tool_keyword = /ffuf\-master\.zip/
                        $string17_ffuf_offensive_tool_keyword = /fuff\s.{0,100}\-input\-shell/
                        $string18_ffuf_offensive_tool_keyword = /fuff\s.{0,100}\-scraperfile/
                        $string19_ffuf_offensive_tool_keyword = /fuff\s.{0,100}\-scrapers/
                        $string20_ffuf_offensive_tool_keyword = /https\:\/\/ffuf\.io\.fi/
                        $string21_ffuf_offensive_tool_keyword = /https\:\/\/ffuf\.io\/FUZZ/
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