rule ffuf
{
    meta:
        description = "Detection patterns for the tool 'ffuf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ffuf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-o\sffuf\.csv/
                        $string2 = /\/ffuf\.git/
                        $string3 = "/ffuf/ffufrc"
                        $string4 = "cd ffuf"
                        $string5 = /ffuf\s.{0,1000}\-input\-cmd/
                        $string6 = /ffuf\s.{0,1000}\-u\shttp/
                        $string7 = "ffuf -c "
                        $string8 = "ffuf -w "
                        $string9 = /ffuf\.exe/
                        $string10 = "ffuf/ffuf"
                        $string11 = /ffuf_.{0,1000}_freebsd_.{0,1000}\.tar\.gz/
                        $string12 = /ffuf_.{0,1000}_linux_.{0,1000}\.tar\.gz/
                        $string13 = /ffuf_.{0,1000}_macOS_.{0,1000}\.tar\.gz/
                        $string14 = /ffuf_.{0,1000}_openbsd_.{0,1000}\.tar\.gz/
                        $string15 = /ffuf_.{0,1000}_windows_.{0,1000}\.zip/
                        $string16 = /ffuf\-master\.zip/
                        $string17 = /fuff\s.{0,1000}\-input\-shell/
                        $string18 = /fuff\s.{0,1000}\-scraperfile/
                        $string19 = /fuff\s.{0,1000}\-scrapers/
                        $string20 = /https\:\/\/ffuf\.io\.fi/
                        $string21 = /https\:\/\/ffuf\.io\/FUZZ/

    condition:
        any of them
}