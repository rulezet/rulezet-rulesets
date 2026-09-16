rule gsecdump
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --dump_lsa" nocase ascii wide
                        $string2 = " --dump_usedhashes" nocase ascii wide
                        $string3 = " --dump_wireless" nocase ascii wide
                        $string4 = /\/gsecdump\-.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\/gsecdump\.exe/ nocase ascii wide
                        $string6 = /\\gsecdump\-.{0,1000}\.exe/ nocase ascii wide
                        $string7 = /\\gsecdump\.exe/ nocase ascii wide
                        $string8 = /\\pipe\\gsecdump_/ nocase ascii wide
                        $string9 = /\>\\gsecdump_/ nocase ascii wide
                        $string10 = "94cae63dcbabb71c5dd43f55fd09caeffdcd7628a02a112fb3cba36698ef72bc" nocase ascii wide
                        $string11 = /gsecdump\-v2b5\.exe/ nocase ascii wide
                        $string12 = /pipe\\\\gsecdump_/ nocase ascii wide

    condition:
        any of them
}