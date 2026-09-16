rule rule_ProxyLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ProxyLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxyLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ProxyLogon_offensive_tool_keyword = /\sproxylogon\.py/ nocase ascii wide
                        $string2_ProxyLogon_offensive_tool_keyword = /\/ProxyLogon\.git/ nocase ascii wide
                        $string3_ProxyLogon_offensive_tool_keyword = /\/proxylogon\.git/ nocase ascii wide
                        $string4_ProxyLogon_offensive_tool_keyword = /\/proxylogon\.py/ nocase ascii wide
                        $string5_ProxyLogon_offensive_tool_keyword = /\[\+\]\sAttempting\sSSRF/ nocase ascii wide
                        $string6_ProxyLogon_offensive_tool_keyword = /\[\+\]\sSuccess\!\sEntering\swebshell/ nocase ascii wide
                        $string7_ProxyLogon_offensive_tool_keyword = /\[WARNING\]\scontinuing\sthe\sattack\sanyway\!/ nocase ascii wide
                        $string8_ProxyLogon_offensive_tool_keyword = /\[WARNING\]\swe\sdidn\'t\sget\s.{0,1000}\scookie\,\sthe\sattack\swill\slikely\sfail\!/ nocase ascii wide
                        $string9_ProxyLogon_offensive_tool_keyword = /\\proxylogon\.py/ nocase ascii wide
                        $string10_ProxyLogon_offensive_tool_keyword = "097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e" nocase ascii wide
                        $string11_ProxyLogon_offensive_tool_keyword = "1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944" nocase ascii wide
                        $string12_ProxyLogon_offensive_tool_keyword = "2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1" nocase ascii wide
                        $string13_ProxyLogon_offensive_tool_keyword = "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea" nocase ascii wide
                        $string14_ProxyLogon_offensive_tool_keyword = "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1" nocase ascii wide
                        $string15_ProxyLogon_offensive_tool_keyword = "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5" nocase ascii wide
                        $string16_ProxyLogon_offensive_tool_keyword = "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d" nocase ascii wide
                        $string17_ProxyLogon_offensive_tool_keyword = "a7de9b97cf6299048be115fdb123c1205b51a850b40c0bb79fb2b5ebad319d6b" nocase ascii wide
                        $string18_ProxyLogon_offensive_tool_keyword = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0" nocase ascii wide
                        $string19_ProxyLogon_offensive_tool_keyword = "C715155F-2BE8-44E0-BD34-2960067874C8" nocase ascii wide
                        $string20_ProxyLogon_offensive_tool_keyword = "c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb" nocase ascii wide
                        $string21_ProxyLogon_offensive_tool_keyword = "hakivvi/proxylogon" nocase ascii wide
                        $string22_ProxyLogon_offensive_tool_keyword = "hausec/ProxyLogon" nocase ascii wide
                        $string23_ProxyLogon_offensive_tool_keyword = "TlRMTVNTUAABAAAABQKIoAAAAAAAAAAAAAAAAAAAAAA=" nocase ascii wide

    condition:
        any of them
}