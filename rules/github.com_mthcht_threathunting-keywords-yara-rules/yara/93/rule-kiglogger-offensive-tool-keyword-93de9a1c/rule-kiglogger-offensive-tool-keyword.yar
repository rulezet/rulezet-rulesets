rule rule_kiglogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kiglogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kiglogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kiglogger_offensive_tool_keyword = "/bin/kidlogger"
                        $string2_kiglogger_offensive_tool_keyword = "/etc/kidlogger"
                        $string3_kiglogger_offensive_tool_keyword = /\/KidLogger\.app\//
                        $string4_kiglogger_offensive_tool_keyword = /\/kidlogger\.desktop/
                        $string5_kiglogger_offensive_tool_keyword = "/srv/kidlogger"
                        $string6_kiglogger_offensive_tool_keyword = "/usr/share/kidlogger"
                        $string7_kiglogger_offensive_tool_keyword = /\\KidLogger\\/ nocase ascii wide
                        $string8_kiglogger_offensive_tool_keyword = /\\KidLogger_is1/ nocase ascii wide
                        $string9_kiglogger_offensive_tool_keyword = /\\Program\sFiles\s\(x86\)\\KidLogger/ nocase ascii wide
                        $string10_kiglogger_offensive_tool_keyword = /\\Software\\Kidlogger/ nocase ascii wide
                        $string11_kiglogger_offensive_tool_keyword = /\\WOW6432Node\\Kidlogger/ nocase ascii wide
                        $string12_kiglogger_offensive_tool_keyword = "3170917f0dbe26d4a09283394af0b9a9e9724589cd650d0b451b2c834aab3bf6" nocase ascii wide
                        $string13_kiglogger_offensive_tool_keyword = "3ec8a46dfacff51b3a19034479c2c68b74c92342e483295152754f939a8d1d31" nocase ascii wide
                        $string14_kiglogger_offensive_tool_keyword = "4fcf193202e55eff267792c86cea4098711b24d3fa0cca8e03027da2ddb3206a" nocase ascii wide
                        $string15_kiglogger_offensive_tool_keyword = "89a687f0367983c98008e9bd2d82e6aa579e24f2d702b6912eeae74b21e85dc9" nocase ascii wide
                        $string16_kiglogger_offensive_tool_keyword = "c8bdc5ce227d167f87797e8f7b3d91d24cd40c0925f5f6406085ad8cdf455617" nocase ascii wide
                        $string17_kiglogger_offensive_tool_keyword = /github\.com\/SafeJKA\/Kidlogger/ nocase ascii wide
                        $string18_kiglogger_offensive_tool_keyword = /KidLogger\-.{0,1000}\.dmg/ nocase ascii wide
                        $string19_kiglogger_offensive_tool_keyword = /kidlogger\.conf/ nocase ascii wide
                        $string20_kiglogger_offensive_tool_keyword = /Kidlogger\.exe/ nocase ascii wide
                        $string21_kiglogger_offensive_tool_keyword = /KidLogger\.lnk/ nocase ascii wide
                        $string22_kiglogger_offensive_tool_keyword = /KidLogger\.net/ nocase ascii wide
                        $string23_kiglogger_offensive_tool_keyword = /KidLogger\.pif/ nocase ascii wide
                        $string24_kiglogger_offensive_tool_keyword = /KidLogger\.url/ nocase ascii wide
                        $string25_kiglogger_offensive_tool_keyword = "kidlogger_install" nocase ascii wide
                        $string26_kiglogger_offensive_tool_keyword = /kidlogger_user\.exe/ nocase ascii wide
                        $string27_kiglogger_offensive_tool_keyword = "make shared dir for kidlogger ini files" nocase ascii wide
                        $string28_kiglogger_offensive_tool_keyword = "package kidlogger" nocase ascii wide
                        $string29_kiglogger_offensive_tool_keyword = /window\-state\@safejka\.eu/ nocase ascii wide

    condition:
        any of them
}