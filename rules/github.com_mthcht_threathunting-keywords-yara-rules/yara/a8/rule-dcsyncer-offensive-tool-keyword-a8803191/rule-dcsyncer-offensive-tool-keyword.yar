rule rule_DCSyncer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DCSyncer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCSyncer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DCSyncer_offensive_tool_keyword = /\/DCSyncer\.git/ nocase ascii wide
                        $string2_DCSyncer_offensive_tool_keyword = "/DCSyncer/releases/download/" nocase ascii wide
                        $string3_DCSyncer_offensive_tool_keyword = "/DCSyncer/tarball/" nocase ascii wide
                        $string4_DCSyncer_offensive_tool_keyword = "/DCSyncer/zipball/" nocase ascii wide
                        $string5_DCSyncer_offensive_tool_keyword = /\\DCSyncer\.sln/ nocase ascii wide
                        $string6_DCSyncer_offensive_tool_keyword = /\\DCSyncer\-master/ nocase ascii wide
                        $string7_DCSyncer_offensive_tool_keyword = "253e716a-ab96-4f87-88c7-052231ec2a12" nocase ascii wide
                        $string8_DCSyncer_offensive_tool_keyword = "802a7ba4f023cd272eba8de0488848a7667ac0eeb3844108bdca994491846404" nocase ascii wide
                        $string9_DCSyncer_offensive_tool_keyword = "b4ce5c82a51a7281bb0d04463c110471ca73f39813ed11c5c51d48d6cf7733e5" nocase ascii wide
                        $string10_DCSyncer_offensive_tool_keyword = "c862cc7e0faabfff2c8e8e58cf7fca200ae534aa5f58857331d1377187a19d3a" nocase ascii wide
                        $string11_DCSyncer_offensive_tool_keyword = /DCSyncer\.exe/ nocase ascii wide
                        $string12_DCSyncer_offensive_tool_keyword = /DCSyncer\-master\.zip/ nocase ascii wide
                        $string13_DCSyncer_offensive_tool_keyword = /DCSyncer\-x64\.exe/ nocase ascii wide
                        $string14_DCSyncer_offensive_tool_keyword = "e94c578a73298e4f6dbb5b3cb4cf4adcea54f6a971e88428f651cd555e5932b0" nocase ascii wide
                        $string15_DCSyncer_offensive_tool_keyword = "eb9c1a8804daed7c8ace37adc87ac66b52e7363666e5af7912bb17695df9b4f4" nocase ascii wide
                        $string16_DCSyncer_offensive_tool_keyword = "notsoshant/DCSyncer" nocase ascii wide

    condition:
        any of them
}