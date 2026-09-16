rule aweray
{
    meta:
        description = "Detection patterns for the tool 'aweray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aweray"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.aweray\.net/ nocase ascii wide
                        $string2 = /\/Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
                        $string3 = /\/Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
                        $string4 = /\\Aweray\sRemote\.lnk/ nocase ascii wide
                        $string5 = /\\Aweray_Remote_.{0,1000}\.exe/ nocase ascii wide
                        $string6 = /\\Aweray_Remote_.{0,1000}\.zip/ nocase ascii wide
                        $string7 = /\\AweSun\.exe/ nocase ascii wide
                        $string8 = /\\Program\sFiles\\Aweray/ nocase ascii wide
                        $string9 = /\\Software\\AweSun\\SunLogin\\SunloginClient/ nocase ascii wide
                        $string10 = ">AweRay Limited<" nocase ascii wide
                        $string11 = /\>AweRay\sPte\.\sLtd\.\</ nocase ascii wide
                        $string12 = /\>AweSun\.exe\</ nocase ascii wide
                        $string13 = ">AweSun<" nocase ascii wide
                        $string14 = /asapi\.aweray\.net/ nocase ascii wide
                        $string15 = /as\-tk\.aweray\.com/ nocase ascii wide
                        $string16 = /as\-tk\.aweray\.com\/track/ nocase ascii wide
                        $string17 = /Aweray_Remote\.exe/ nocase ascii wide
                        $string18 = /awerayimg\.com/ nocase ascii wide
                        $string19 = /client\-api\.aweray\.com/ nocase ascii wide
                        $string20 = /https\:\/\/sun\.aweray\.com\/.{0,1000}\/download/ nocase ascii wide
                        $string21 = /install\.bat\sAweSun/ nocase ascii wide
                        $string22 = /netsh\s\sadvfirewall\sfirewall\s.{0,1000}\srule\sname\=\\"AweSun/ nocase ascii wide

    condition:
        any of them
}