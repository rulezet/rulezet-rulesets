rule AutoC2
{
    meta:
        description = "Detection patterns for the tool 'AutoC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCred_Dump\.sh/ nocase ascii wide
                        $string2 = /\sDefense_Evasion\.sh/ nocase ascii wide
                        $string3 = /\sExfil\.sh/ nocase ascii wide
                        $string4 = /\sHak5\.sh/ nocase ascii wide
                        $string5 = /\sPersistence\.sh/ nocase ascii wide
                        $string6 = /\sPriv_Esc\.sh/ nocase ascii wide
                        $string7 = /\.\/Exfil\.sh/
                        $string8 = /\.\/Phishing\.sh/
                        $string9 = /\/Cred_Dump\.sh/ nocase ascii wide
                        $string10 = /\/Defense_Evasion\.sh/
                        $string11 = /\/Hak5\.sh/
                        $string12 = "/opt/Password_Cracking/"
                        $string13 = /\/Persistence\.sh/
                        $string14 = /\/Phishing\.sh/
                        $string15 = /\/Priv_Esc\.sh/ nocase ascii wide
                        $string16 = /AutoC2\.sh/ nocase ascii wide
                        $string17 = /AutoC2\/All\.sh/ nocase ascii wide
                        $string18 = "AutoC2/C2" nocase ascii wide
                        $string19 = "AutoC2/Dependencies" nocase ascii wide
                        $string20 = "AutoC2/Initial_Access" nocase ascii wide
                        $string21 = /AutoC2\/Lateral\.sh/ nocase ascii wide
                        $string22 = "AutoC2/Payload_Development" nocase ascii wide
                        $string23 = "AutoC2/Recon" nocase ascii wide
                        $string24 = "AutoC2/Situational_Awareness" nocase ascii wide
                        $string25 = /AutoC2\/Social\.sh/ nocase ascii wide
                        $string26 = "AutoC2/Staging" nocase ascii wide
                        $string27 = /AutoC2\/Web\.sh/ nocase ascii wide
                        $string28 = /AutoC2\/Wireless\.sh/ nocase ascii wide
                        $string29 = "AutoC2/Wordlists" nocase ascii wide
                        $string30 = /Password_Cracking\.sh/ nocase ascii wide

    condition:
        any of them
}