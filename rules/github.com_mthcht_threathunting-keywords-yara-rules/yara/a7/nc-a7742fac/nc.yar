rule nc
{
    meta:
        description = "Detection patterns for the tool 'nc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\s\>\scron\s\&\&\scrontab\scron/
                        $string2 = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\>\s.{0,1000}\scrontab\scron/
                        $string3 = "/nc64 -i "
                        $string4 = "/nc64 -lvp "
                        $string5 = "/nc64 -zv "
                        $string6 = /\\nc\.exe\s\-Ldp\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
                        $string7 = /\\nc64\.exe\s\-i\s/ nocase ascii wide
                        $string8 = /\\nc64\.exe\s\-i/ nocase ascii wide
                        $string9 = /\\nc64\.exe\s\-lvp\s/ nocase ascii wide
                        $string10 = /\\nc64\.exe\s\-zv\s/ nocase ascii wide
                        $string11 = /\\nc64\.exe\\"\s\-i\s/ nocase ascii wide
                        $string12 = /\\nc64\.exe\\"\s\-lvp\s/ nocase ascii wide
                        $string13 = /\\nc64\.exe\\"\s\-zv\s/ nocase ascii wide
                        $string14 = /\\ncat.{0,1000}\s\-e\scmd\.exe\s\-\-keep\-open/ nocase ascii wide
                        $string15 = /\\windows\\currentversion\\run\s\-v\snetcat\s/ nocase ascii wide
                        $string16 = /echo\snc\s\-l\s\-p\s.{0,1000}\s\>\s.{0,1000}\.bat/ nocase ascii wide
                        $string17 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s.{0,1000}\.bat/ nocase ascii wide
                        $string18 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string19 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
                        $string20 = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,1000}\-/ nocase ascii wide
                        $string21 = /nc\s\-z\s\-v\s.{0,1000}\s/ nocase ascii wide
                        $string22 = /nc\.exe\s.{0,1000}\s\-e\scmd\.exe\\"\s\/sc\sONCE\s/ nocase ascii wide
                        $string23 = /nc\.exe\s\-e\s\\windows\\system32\\cmd\.exe\s.{0,1000}\sstart\=\sauto/ nocase ascii wide

    condition:
        any of them
}