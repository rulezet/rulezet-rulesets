rule CheeseTools
{
    meta:
        description = "Detection patterns for the tool 'CheeseTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheeseTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --am-si-bypass=" nocase ascii wide
                        $string2 = " --reflective-injection " nocase ascii wide
                        $string3 = " --wldp-bypass=" nocase ascii wide
                        $string4 = /\/CheeseTools\.git/ nocase ascii wide
                        $string5 = "0DD419E5-D7B3-4360-874E-5838A7519355" nocase ascii wide
                        $string6 = "36F9C306-5F45-4946-A259-610C05BD90DF" nocase ascii wide
                        $string7 = "A8FE1F5C-6B2A-4417-907F-4F6EDE9C15A3" nocase ascii wide
                        $string8 = /AmsiBypass\.cs/ nocase ascii wide
                        $string9 = "AS 'Login that can be impersonated'" nocase ascii wide
                        $string10 = "as 'Owner that can be impersonated'" nocase ascii wide
                        $string11 = /C\:\\Users\\Public\\perm\.txt/ nocase ascii wide
                        $string12 = /C\:\\Users\\Public\\test\.txt/ nocase ascii wide
                        $string13 = "C526B877-6AFF-413C-BC03-1837FB63BC22" nocase ascii wide
                        $string14 = "CD3578F6-01B7-48C9-9140-1AFA44B3A7C0" nocase ascii wide
                        $string15 = /CheeseDCOM\.exe/ nocase ascii wide
                        $string16 = /CheeseExec\.csproj/ nocase ascii wide
                        $string17 = /CheeseExec\.exe/ nocase ascii wide
                        $string18 = /CheesePS\.csproj/ nocase ascii wide
                        $string19 = /CheesePS\.exe/ nocase ascii wide
                        $string20 = /CheeseRDP\.exe/ nocase ascii wide
                        $string21 = /CheeseSQL\.exe/ nocase ascii wide
                        $string22 = /CheeseTools\.sln/ nocase ascii wide
                        $string23 = "CheeseTools-master" nocase ascii wide
                        $string24 = "klezVirus/CheeseTools" nocase ascii wide
                        $string25 = /SELECT\sSYSTEM_USER\sas\s\'Logged\sin\sas\'.{0,1000}\sCURRENT_USER\sas\s\'Mapped\sas\'/ nocase ascii wide
                        $string26 = /WldpBypass\.cs/ nocase ascii wide

    condition:
        any of them
}