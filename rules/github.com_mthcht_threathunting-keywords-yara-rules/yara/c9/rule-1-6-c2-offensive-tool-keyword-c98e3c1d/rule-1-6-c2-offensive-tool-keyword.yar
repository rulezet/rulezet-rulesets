rule rule__1_6_C2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '1.6-C2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1.6-C2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__1_6_C2_offensive_tool_keyword = /\/1\.6\-C2\.git/ nocase ascii wide
                        $string2__1_6_C2_offensive_tool_keyword = /\\1\.6\-C2\-main\.zip/ nocase ascii wide
                        $string3__1_6_C2_offensive_tool_keyword = /\\1_6_C2\.exe/ nocase ascii wide
                        $string4__1_6_C2_offensive_tool_keyword = /\]\sReceived\sRCON\schallenge\:\s/ nocase ascii wide
                        $string5__1_6_C2_offensive_tool_keyword = "01a82d6612d5698da1badc96841f2d6835e26ee95af3c536411b6d1b086da811" nocase ascii wide
                        $string6__1_6_C2_offensive_tool_keyword = "35d3030e079a68ce10e998b5140d66fbb54b4a6e7f8ed090bf918abc42175dce" nocase ascii wide
                        $string7__1_6_C2_offensive_tool_keyword = "c07d3356-7f9b-45e0-a4f7-7b1487d966b8" nocase ascii wide
                        $string8__1_6_C2_offensive_tool_keyword = /eversinc33\/1\.6\-C2/ nocase ascii wide
                        $string9__1_6_C2_offensive_tool_keyword = /getHostnameFromCVARS\(/ nocase ascii wide

    condition:
        any of them
}