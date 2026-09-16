rule localtunnels
{
    meta:
        description = "Detection patterns for the tool 'localtunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install localtunnel" nocase ascii wide
                        $string2 = " localtunnel-server" nocase ascii wide
                        $string3 = /\/localtunnel\.git/ nocase ascii wide
                        $string4 = /\/localtunnel\-server\.git/ nocase ascii wide
                        $string5 = "37e85dd1f3987fcc566c1b29bda5b94e4b2fd129a39cc7eeba3af7a69a0cdb09" nocase ascii wide
                        $string6 = "6f44dd5e572279979a9a59b0186a9fb2805be4c6decbcc438cf2b9d2c17f3a42" nocase ascii wide
                        $string7 = "aba729428bafe6508191a79e06c7399a19cf80bf0c382eecca951655aab6e00a" nocase ascii wide
                        $string8 = "bin/lt --host https://" nocase ascii wide
                        $string9 = /https\:\/\/.{0,1000}\.localtunnel\.me/ nocase ascii wide
                        $string10 = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11 = /localtunnel\.github\.io\/www\// nocase ascii wide
                        $string12 = "localtunnel/localtunnel" nocase ascii wide
                        $string13 = "localtunnel/nginx" nocase ascii wide
                        $string14 = "localtunnel/server" nocase ascii wide
                        $string15 = "npm install -g localtunnel" nocase ascii wide
                        $string16 = "npm install -g localtunnel" nocase ascii wide
                        $string17 = "npx localtunnel --port " nocase ascii wide

    condition:
        any of them
}