rule rule_aweray_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'aweray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aweray"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_aweray_greyware_tool_keyword = /\.aweray\.net/ nocase ascii wide
                        $string2_aweray_greyware_tool_keyword = /\/Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
                        $string3_aweray_greyware_tool_keyword = /\/Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
                        $string4_aweray_greyware_tool_keyword = /\\Aweray\sRemote\.lnk/ nocase ascii wide
                        $string5_aweray_greyware_tool_keyword = /\\Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
                        $string6_aweray_greyware_tool_keyword = /\\Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
                        $string7_aweray_greyware_tool_keyword = /\\AweSun\.exe/ nocase ascii wide
                        $string8_aweray_greyware_tool_keyword = /\\Program\sFiles\\Aweray/ nocase ascii wide
                        $string9_aweray_greyware_tool_keyword = /\\Software\\AweSun\\SunLogin\\SunloginClient/ nocase ascii wide
                        $string10_aweray_greyware_tool_keyword = ">AweRay Limited<" nocase ascii wide
                        $string11_aweray_greyware_tool_keyword = /\>AweRay\sPte\.\sLtd\.\</ nocase ascii wide
                        $string12_aweray_greyware_tool_keyword = /\>AweSun\.exe\</ nocase ascii wide
                        $string13_aweray_greyware_tool_keyword = ">AweSun<" nocase ascii wide
                        $string14_aweray_greyware_tool_keyword = /asapi\.aweray\.net/ nocase ascii wide
                        $string15_aweray_greyware_tool_keyword = /as\-tk\.aweray\.com/ nocase ascii wide
                        $string16_aweray_greyware_tool_keyword = /as\-tk\.aweray\.com\/track/ nocase ascii wide
                        $string17_aweray_greyware_tool_keyword = /Aweray_Remote\.exe/ nocase ascii wide
                        $string18_aweray_greyware_tool_keyword = /awerayimg\.com/ nocase ascii wide
                        $string19_aweray_greyware_tool_keyword = /client\-api\.aweray\.com/ nocase ascii wide
                        $string20_aweray_greyware_tool_keyword = /https\:\/\/sun\.aweray\.com\/.{0,1000}\/download/ nocase ascii wide
                        $string21_aweray_greyware_tool_keyword = /install\.bat\sAweSun/ nocase ascii wide
                        $string22_aweray_greyware_tool_keyword = /netsh\s\sadvfirewall\sfirewall\s.{0,1000}\srule\sname\=\\"AweSun/ nocase ascii wide

    condition:
        any of them
}