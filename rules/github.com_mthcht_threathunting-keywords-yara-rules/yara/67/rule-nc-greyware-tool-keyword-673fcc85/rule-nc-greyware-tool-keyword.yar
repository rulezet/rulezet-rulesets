rule rule_nc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nc_greyware_tool_keyword = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\s\>\scron\s\&\&\scrontab\scron/
                        $string2_nc_greyware_tool_keyword = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\>\s.{0,1000}\scrontab\scron/
                        $string3_nc_greyware_tool_keyword = "/nc64 -i "
                        $string4_nc_greyware_tool_keyword = "/nc64 -lvp "
                        $string5_nc_greyware_tool_keyword = "/nc64 -zv "
                        $string6_nc_greyware_tool_keyword = /\\nc\.exe\s\-Ldp\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
                        $string7_nc_greyware_tool_keyword = /\\nc64\.exe\s\-i\s/ nocase ascii wide
                        $string8_nc_greyware_tool_keyword = /\\nc64\.exe\s\-i/ nocase ascii wide
                        $string9_nc_greyware_tool_keyword = /\\nc64\.exe\s\-lvp\s/ nocase ascii wide
                        $string10_nc_greyware_tool_keyword = /\\nc64\.exe\s\-zv\s/ nocase ascii wide
                        $string11_nc_greyware_tool_keyword = /\\nc64\.exe\\"\s\-i\s/ nocase ascii wide
                        $string12_nc_greyware_tool_keyword = /\\nc64\.exe\\"\s\-lvp\s/ nocase ascii wide
                        $string13_nc_greyware_tool_keyword = /\\nc64\.exe\\"\s\-zv\s/ nocase ascii wide
                        $string14_nc_greyware_tool_keyword = /\\ncat.{0,1000}\s\-e\scmd\.exe\s\-\-keep\-open/ nocase ascii wide
                        $string15_nc_greyware_tool_keyword = /\\windows\\currentversion\\run\s\-v\snetcat\s/ nocase ascii wide
                        $string16_nc_greyware_tool_keyword = /echo\snc\s\-l\s\-p\s.{0,1000}\s\>\s.{0,1000}\.bat/ nocase ascii wide
                        $string17_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s.{0,1000}\.bat/ nocase ascii wide
                        $string18_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s\/bin\/bash/
                        $string19_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
                        $string20_nc_greyware_tool_keyword = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,1000}\-/ nocase ascii wide
                        $string21_nc_greyware_tool_keyword = /nc\s\-z\s\-v\s.{0,1000}\s/ nocase ascii wide
                        $string22_nc_greyware_tool_keyword = /nc\.exe\s.{0,1000}\s\-e\scmd\.exe\\"\s\/sc\sONCE\s/ nocase ascii wide
                        $string23_nc_greyware_tool_keyword = /nc\.exe\s\-e\s\\windows\\system32\\cmd\.exe\s.{0,1000}\sstart\=\sauto/ nocase ascii wide

    condition:
        any of them
}