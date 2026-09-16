rule rule_keywa7_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'keywa7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keywa7"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_keywa7_offensive_tool_keyword = /\.exe\s\-\-lhost\s127\.0\.0\.1\s\-\-lport\s.{0,1000}\s\-\-rhost\s/ nocase ascii wide
                        $string2_keywa7_offensive_tool_keyword = "/keywa7/releases/download/" nocase ascii wide
                        $string3_keywa7_offensive_tool_keyword = "2d171b19906b039677a1213f32d27a9e1e4a0b96e9e071f7a8e8bd8a72e46243" nocase ascii wide
                        $string4_keywa7_offensive_tool_keyword = "571e01606bbaaab8febd88396cb3dd97eb8e883e6597d6a881f8c736eff5a05d" nocase ascii wide
                        $string5_keywa7_offensive_tool_keyword = "5c2a6754f5b9e92a49dfb22ce0644d0e4afaecc5b7a8d7e4714dfb578917c7d8" nocase ascii wide
                        $string6_keywa7_offensive_tool_keyword = "c7c2b1295dbc6b5b13330310465c771108fdeff7e7b37447bc449f6c535cfa62" nocase ascii wide
                        $string7_keywa7_offensive_tool_keyword = "d5aa5ef1208264ae918f0e285d358189f66d1166093657f0240a762220bd6a74" nocase ascii wide
                        $string8_keywa7_offensive_tool_keyword = "fb74046f994a179d004abc1f9a6a00ffa8867dc011d2e2e9ca432fe9225227c2" nocase ascii wide
                        $string9_keywa7_offensive_tool_keyword = "keywa7/keywa7" nocase ascii wide

    condition:
        any of them
}