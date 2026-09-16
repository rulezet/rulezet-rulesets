rule rule_BypassAddUser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BypassAddUser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BypassAddUser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BypassAddUser_offensive_tool_keyword = /\/BypassAddUser\.exe/ nocase ascii wide
                        $string2_BypassAddUser_offensive_tool_keyword = /\/BypassAddUser\.git/ nocase ascii wide
                        $string3_BypassAddUser_offensive_tool_keyword = "/BypassAddUser/releases/download/" nocase ascii wide
                        $string4_BypassAddUser_offensive_tool_keyword = "/BypassAddUser/tarball/" nocase ascii wide
                        $string5_BypassAddUser_offensive_tool_keyword = "/BypassAddUser/zipball/" nocase ascii wide
                        $string6_BypassAddUser_offensive_tool_keyword = /\\BypassAddUser\.exe/ nocase ascii wide
                        $string7_BypassAddUser_offensive_tool_keyword = /\\BypassAddUser\-master/ nocase ascii wide
                        $string8_BypassAddUser_offensive_tool_keyword = "2e10ff03c18dcdeda7ccb185154f17ae29f54920a489edd270c535d7813366e0" nocase ascii wide
                        $string9_BypassAddUser_offensive_tool_keyword = "446dded3a070a586ff2c25e9a17784ed650e594e9a08b703c4cbd2662b95c94c" nocase ascii wide
                        $string10_BypassAddUser_offensive_tool_keyword = "559b3c946bba5edb17f646da5b0b4e259ad3af12aafea6744b1502230419cd6b" nocase ascii wide
                        $string11_BypassAddUser_offensive_tool_keyword = "5f76ace41e6efb7af838f936421f53fd66eed1efdcfde03950f3432816fadeed" nocase ascii wide
                        $string12_BypassAddUser_offensive_tool_keyword = "7FDCF4E0-2E6A-43D5-80FB-0A1A40AB3D93" nocase ascii wide
                        $string13_BypassAddUser_offensive_tool_keyword = /BypassAddUser\.exe\s\-/ nocase ascii wide
                        $string14_BypassAddUser_offensive_tool_keyword = "d8512753450da47e16944a61c468294e7a2617f244bbe6595fedf0249af0bba3" nocase ascii wide
                        $string15_BypassAddUser_offensive_tool_keyword = "e64efe84d00a0c06cc9672f7d2c96e39c6ef7ef4b8ff1671f35e369a03431af9" nocase ascii wide
                        $string16_BypassAddUser_offensive_tool_keyword = "TryA9ain/BypassAddUser" nocase ascii wide

    condition:
        any of them
}