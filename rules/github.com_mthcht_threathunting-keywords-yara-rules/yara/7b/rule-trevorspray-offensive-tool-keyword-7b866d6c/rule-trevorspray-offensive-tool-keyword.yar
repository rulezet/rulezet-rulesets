rule rule_TREVORspray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TREVORspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TREVORspray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TREVORspray_offensive_tool_keyword = /\/TREVORspray\.git/ nocase ascii wide
                        $string2_TREVORspray_offensive_tool_keyword = /\/trevorspray\.log/ nocase ascii wide
                        $string3_TREVORspray_offensive_tool_keyword = /\/tried_logins\.txt/
                        $string4_TREVORspray_offensive_tool_keyword = "blacklanternsecurity/trevorproxy" nocase ascii wide
                        $string5_TREVORspray_offensive_tool_keyword = "blacklanternsecurity/TREVORspray" nocase ascii wide
                        $string6_TREVORspray_offensive_tool_keyword = "import BaseSprayModule" nocase ascii wide
                        $string7_TREVORspray_offensive_tool_keyword = /spray.{0,1000}\s\-\-recon\s.{0,1000}\..{0,1000}\s\-u\s.{0,1000}\.txt\s\-\-threads\s10/ nocase ascii wide
                        $string8_TREVORspray_offensive_tool_keyword = "TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA" nocase ascii wide
                        $string9_TREVORspray_offensive_tool_keyword = "trevorproxy ssh" nocase ascii wide
                        $string10_TREVORspray_offensive_tool_keyword = "trevorproxy subnet" nocase ascii wide
                        $string11_TREVORspray_offensive_tool_keyword = "trevorspray -" nocase ascii wide
                        $string12_TREVORspray_offensive_tool_keyword = /trevorspray\.cli/ nocase ascii wide
                        $string13_TREVORspray_offensive_tool_keyword = /trevorspray\.enumerators/ nocase ascii wide
                        $string14_TREVORspray_offensive_tool_keyword = /trevorspray\.looters/ nocase ascii wide
                        $string15_TREVORspray_offensive_tool_keyword = /trevorspray\.py/ nocase ascii wide
                        $string16_TREVORspray_offensive_tool_keyword = /trevorspray\.sprayers/ nocase ascii wide
                        $string17_TREVORspray_offensive_tool_keyword = /trevorspray\/existent_users\.txt/ nocase ascii wide
                        $string18_TREVORspray_offensive_tool_keyword = /trevorspray\/valid_logins\.txt/ nocase ascii wide
                        $string19_TREVORspray_offensive_tool_keyword = "TREVORspray-dev" nocase ascii wide
                        $string20_TREVORspray_offensive_tool_keyword = "TREVORspray-master" nocase ascii wide
                        $string21_TREVORspray_offensive_tool_keyword = "TREVORspray-trevorspray" nocase ascii wide
                        $string22_TREVORspray_offensive_tool_keyword = "Your Moms Smart Vibrator" nocase ascii wide

    condition:
        any of them
}