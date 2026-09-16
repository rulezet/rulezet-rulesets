rule rule_gsecdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gsecdump_offensive_tool_keyword = " --dump_lsa" nocase ascii wide
                        $string2_gsecdump_offensive_tool_keyword = " --dump_usedhashes" nocase ascii wide
                        $string3_gsecdump_offensive_tool_keyword = " --dump_wireless" nocase ascii wide
                        $string4_gsecdump_offensive_tool_keyword = /\/gsecdump\-.{0,1000}\.exe/ nocase ascii wide
                        $string5_gsecdump_offensive_tool_keyword = /\/gsecdump\.exe/ nocase ascii wide
                        $string6_gsecdump_offensive_tool_keyword = /\\gsecdump\-.{0,1000}\.exe/ nocase ascii wide
                        $string7_gsecdump_offensive_tool_keyword = /\\gsecdump\.exe/ nocase ascii wide
                        $string8_gsecdump_offensive_tool_keyword = /\\pipe\\gsecdump_/ nocase ascii wide
                        $string9_gsecdump_offensive_tool_keyword = /\>\\gsecdump_/ nocase ascii wide
                        $string10_gsecdump_offensive_tool_keyword = "94cae63dcbabb71c5dd43f55fd09caeffdcd7628a02a112fb3cba36698ef72bc" nocase ascii wide
                        $string11_gsecdump_offensive_tool_keyword = /gsecdump\-v2b5\.exe/ nocase ascii wide
                        $string12_gsecdump_offensive_tool_keyword = /pipe\\\\gsecdump_/ nocase ascii wide

    condition:
        any of them
}