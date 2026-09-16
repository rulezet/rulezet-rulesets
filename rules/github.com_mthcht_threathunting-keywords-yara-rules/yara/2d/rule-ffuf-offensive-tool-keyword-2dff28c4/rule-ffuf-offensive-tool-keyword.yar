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
                        $string5_ffuf_offensive_tool_keyword = /ffuf\s.{0,1000}\-input\-cmd/
                        $string6_ffuf_offensive_tool_keyword = /ffuf\s.{0,1000}\-u\shttp/
                        $string7_ffuf_offensive_tool_keyword = "ffuf -c "
                        $string8_ffuf_offensive_tool_keyword = "ffuf -w "
                        $string9_ffuf_offensive_tool_keyword = /ffuf\.exe/
                        $string10_ffuf_offensive_tool_keyword = "ffuf/ffuf"
                        $string11_ffuf_offensive_tool_keyword = /ffuf_.{0,1000}_freebsd_.{0,1000}\.tar\.gz/
                        $string12_ffuf_offensive_tool_keyword = /ffuf_.{0,1000}_linux_.{0,1000}\.tar\.gz/
                        $string13_ffuf_offensive_tool_keyword = /ffuf_.{0,1000}_macOS_.{0,1000}\.tar\.gz/
                        $string14_ffuf_offensive_tool_keyword = /ffuf_.{0,1000}_openbsd_.{0,1000}\.tar\.gz/
                        $string15_ffuf_offensive_tool_keyword = /ffuf_.{0,1000}_windows_.{0,1000}\.zip/
                        $string16_ffuf_offensive_tool_keyword = /ffuf\-master\.zip/
                        $string17_ffuf_offensive_tool_keyword = /fuff\s.{0,1000}\-input\-shell/
                        $string18_ffuf_offensive_tool_keyword = /fuff\s.{0,1000}\-scraperfile/
                        $string19_ffuf_offensive_tool_keyword = /fuff\s.{0,1000}\-scrapers/
                        $string20_ffuf_offensive_tool_keyword = /https\:\/\/ffuf\.io\.fi/
                        $string21_ffuf_offensive_tool_keyword = /https\:\/\/ffuf\.io\/FUZZ/

    condition:
        any of them
}