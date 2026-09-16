rule rule_CheeseTools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CheeseTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CheeseTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CheeseTools_offensive_tool_keyword = " --am-si-bypass=" nocase ascii wide
                        $string2_CheeseTools_offensive_tool_keyword = " --reflective-injection " nocase ascii wide
                        $string3_CheeseTools_offensive_tool_keyword = " --wldp-bypass=" nocase ascii wide
                        $string4_CheeseTools_offensive_tool_keyword = /\/CheeseTools\.git/ nocase ascii wide
                        $string5_CheeseTools_offensive_tool_keyword = "0DD419E5-D7B3-4360-874E-5838A7519355" nocase ascii wide
                        $string6_CheeseTools_offensive_tool_keyword = "36F9C306-5F45-4946-A259-610C05BD90DF" nocase ascii wide
                        $string7_CheeseTools_offensive_tool_keyword = "A8FE1F5C-6B2A-4417-907F-4F6EDE9C15A3" nocase ascii wide
                        $string8_CheeseTools_offensive_tool_keyword = /AmsiBypass\.cs/ nocase ascii wide
                        $string9_CheeseTools_offensive_tool_keyword = "AS 'Login that can be impersonated'" nocase ascii wide
                        $string10_CheeseTools_offensive_tool_keyword = "as 'Owner that can be impersonated'" nocase ascii wide
                        $string11_CheeseTools_offensive_tool_keyword = /C\:\\Users\\Public\\perm\.txt/ nocase ascii wide
                        $string12_CheeseTools_offensive_tool_keyword = /C\:\\Users\\Public\\test\.txt/ nocase ascii wide
                        $string13_CheeseTools_offensive_tool_keyword = "C526B877-6AFF-413C-BC03-1837FB63BC22" nocase ascii wide
                        $string14_CheeseTools_offensive_tool_keyword = "CD3578F6-01B7-48C9-9140-1AFA44B3A7C0" nocase ascii wide
                        $string15_CheeseTools_offensive_tool_keyword = /CheeseDCOM\.exe/ nocase ascii wide
                        $string16_CheeseTools_offensive_tool_keyword = /CheeseExec\.csproj/ nocase ascii wide
                        $string17_CheeseTools_offensive_tool_keyword = /CheeseExec\.exe/ nocase ascii wide
                        $string18_CheeseTools_offensive_tool_keyword = /CheesePS\.csproj/ nocase ascii wide
                        $string19_CheeseTools_offensive_tool_keyword = /CheesePS\.exe/ nocase ascii wide
                        $string20_CheeseTools_offensive_tool_keyword = /CheeseRDP\.exe/ nocase ascii wide
                        $string21_CheeseTools_offensive_tool_keyword = /CheeseSQL\.exe/ nocase ascii wide
                        $string22_CheeseTools_offensive_tool_keyword = /CheeseTools\.sln/ nocase ascii wide
                        $string23_CheeseTools_offensive_tool_keyword = "CheeseTools-master" nocase ascii wide
                        $string24_CheeseTools_offensive_tool_keyword = "klezVirus/CheeseTools" nocase ascii wide
                        $string25_CheeseTools_offensive_tool_keyword = /SELECT\sSYSTEM_USER\sas\s\'Logged\sin\sas\'.{0,1000}\sCURRENT_USER\sas\s\'Mapped\sas\'/ nocase ascii wide
                        $string26_CheeseTools_offensive_tool_keyword = /WldpBypass\.cs/ nocase ascii wide

    condition:
        any of them
}