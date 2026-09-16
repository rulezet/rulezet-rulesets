rule ADAPE_Script
{
    meta:
        description = "Detection patterns for the tool 'ADAPE-Script' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADAPE-Script"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " \"Sniffy boi sniffin\"" nocase ascii wide
                        $string2 = /\sADAPE\.ps1/ nocase ascii wide
                        $string3 = /\$Kerberoast/ nocase ascii wide
                        $string4 = /\.ps1\s\-GPP\s\-PView\s\-Kerberoast/ nocase ascii wide
                        $string5 = /\.ps1\s\-PrivEsc/ nocase ascii wide
                        $string6 = /\/ADAPE\.ps1/ nocase ascii wide
                        $string7 = /\/ADAPE\-Script\.git/ nocase ascii wide
                        $string8 = /\/Inveigh\.ps1/ nocase ascii wide
                        $string9 = /\/PowerUp\.ps1/ nocase ascii wide
                        $string10 = /\/PowerView\.ps1/ nocase ascii wide
                        $string11 = /\/PrivEsc\.psm1/ nocase ascii wide
                        $string12 = /\/PView\.psm1/ nocase ascii wide
                        $string13 = /\\ADAPE\.ps1/ nocase ascii wide
                        $string14 = /\\ExploitableSystem\.txt/ nocase ascii wide
                        $string15 = /\\PrivEsc\.txt/ nocase ascii wide
                        $string16 = /\\ShareFinder\.txt/ nocase ascii wide
                        $string17 = "7f99e59cb3242638aa4967180674b98dd770fae51a85ff364238faf52e02a586" nocase ascii wide
                        $string18 = "Attemping WPAD, LLMNR, and NBTNS poisoning" nocase ascii wide
                        $string19 = "Author: @haus3c" nocase ascii wide
                        $string20 = "Collecting Privesc methods" nocase ascii wide
                        $string21 = "function PrivEsc" nocase ascii wide
                        $string22 = "Get-ExploitableSystem -Verbose" nocase ascii wide
                        $string23 = /Get\-GPPPassword\.ps1/ nocase ascii wide
                        $string24 = "hausec/ADAPE-Script" nocase ascii wide
                        $string25 = /Import\-Module\s.{0,1000}\/PView\.psm1/ nocase ascii wide
                        $string26 = "Invoke-Kerberoast" nocase ascii wide
                        $string27 = "Invoke-ShareFinder -CheckShareAccess" nocase ascii wide

    condition:
        any of them
}