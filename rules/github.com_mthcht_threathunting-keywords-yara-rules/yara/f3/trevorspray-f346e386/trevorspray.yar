rule TREVORspray
{
    meta:
        description = "Detection patterns for the tool 'TREVORspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TREVORspray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/TREVORspray\.git/ nocase ascii wide
                        $string2 = /\/trevorspray\.log/ nocase ascii wide
                        $string3 = /\/tried_logins\.txt/
                        $string4 = "blacklanternsecurity/trevorproxy" nocase ascii wide
                        $string5 = "blacklanternsecurity/TREVORspray" nocase ascii wide
                        $string6 = "import BaseSprayModule" nocase ascii wide
                        $string7 = /spray.{0,1000}\s\-\-recon\s.{0,1000}\..{0,1000}\s\-u\s.{0,1000}\.txt\s\-\-threads\s10/ nocase ascii wide
                        $string8 = "TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA" nocase ascii wide
                        $string9 = "trevorproxy ssh" nocase ascii wide
                        $string10 = "trevorproxy subnet" nocase ascii wide
                        $string11 = "trevorspray -" nocase ascii wide
                        $string12 = /trevorspray\.cli/ nocase ascii wide
                        $string13 = /trevorspray\.enumerators/ nocase ascii wide
                        $string14 = /trevorspray\.looters/ nocase ascii wide
                        $string15 = /trevorspray\.py/ nocase ascii wide
                        $string16 = /trevorspray\.sprayers/ nocase ascii wide
                        $string17 = /trevorspray\/existent_users\.txt/ nocase ascii wide
                        $string18 = /trevorspray\/valid_logins\.txt/ nocase ascii wide
                        $string19 = "TREVORspray-dev" nocase ascii wide
                        $string20 = "TREVORspray-master" nocase ascii wide
                        $string21 = "TREVORspray-trevorspray" nocase ascii wide
                        $string22 = "Your Moms Smart Vibrator" nocase ascii wide

    condition:
        any of them
}