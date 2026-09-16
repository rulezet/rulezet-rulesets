rule rule_localtunnels_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localtunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_localtunnels_greyware_tool_keyword = " install localtunnel" nocase ascii wide
                        $string2_localtunnels_greyware_tool_keyword = " localtunnel-server" nocase ascii wide
                        $string3_localtunnels_greyware_tool_keyword = /\/localtunnel\.git/ nocase ascii wide
                        $string4_localtunnels_greyware_tool_keyword = /\/localtunnel\-server\.git/ nocase ascii wide
                        $string5_localtunnels_greyware_tool_keyword = "37e85dd1f3987fcc566c1b29bda5b94e4b2fd129a39cc7eeba3af7a69a0cdb09" nocase ascii wide
                        $string6_localtunnels_greyware_tool_keyword = "6f44dd5e572279979a9a59b0186a9fb2805be4c6decbcc438cf2b9d2c17f3a42" nocase ascii wide
                        $string7_localtunnels_greyware_tool_keyword = "aba729428bafe6508191a79e06c7399a19cf80bf0c382eecca951655aab6e00a" nocase ascii wide
                        $string8_localtunnels_greyware_tool_keyword = "bin/lt --host https://" nocase ascii wide
                        $string9_localtunnels_greyware_tool_keyword = /https\:\/\/.{0,1000}\.localtunnel\.me/ nocase ascii wide
                        $string10_localtunnels_greyware_tool_keyword = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11_localtunnels_greyware_tool_keyword = /localtunnel\.github\.io\/www\// nocase ascii wide
                        $string12_localtunnels_greyware_tool_keyword = "localtunnel/localtunnel" nocase ascii wide
                        $string13_localtunnels_greyware_tool_keyword = "localtunnel/nginx" nocase ascii wide
                        $string14_localtunnels_greyware_tool_keyword = "localtunnel/server" nocase ascii wide
                        $string15_localtunnels_greyware_tool_keyword = "npm install -g localtunnel" nocase ascii wide
                        $string16_localtunnels_greyware_tool_keyword = "npm install -g localtunnel" nocase ascii wide
                        $string17_localtunnels_greyware_tool_keyword = "npx localtunnel --port " nocase ascii wide

    condition:
        any of them
}