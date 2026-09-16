rule rule_Proxifier_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Proxifier' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxifier"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Proxifier_greyware_tool_keyword = " stop ProxifierDrv" nocase ascii wide
                        $string2_Proxifier_greyware_tool_keyword = /\/Proxifier\.app\/Contents\/MacOS\/Proxifier/ nocase ascii wide
                        $string3_Proxifier_greyware_tool_keyword = /\/Proxifier\.exe/ nocase ascii wide
                        $string4_Proxifier_greyware_tool_keyword = /\/Proxifier\/Proxifier\.app\// nocase ascii wide
                        $string5_Proxifier_greyware_tool_keyword = /\/ProxifierPE\.zip/ nocase ascii wide
                        $string6_Proxifier_greyware_tool_keyword = /\/ProxifierSetup\.exe/ nocase ascii wide
                        $string7_Proxifier_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\Proxifier\sPE\\/ nocase ascii wide
                        $string8_Proxifier_greyware_tool_keyword = /\\AppData\\Local\\Temp\\Proxifier\sPE\\/ nocase ascii wide
                        $string9_Proxifier_greyware_tool_keyword = /\\Proxifier\sService\sManager\.lnk/ nocase ascii wide
                        $string10_Proxifier_greyware_tool_keyword = /\\Proxifier\.exe/ nocase ascii wide
                        $string11_Proxifier_greyware_tool_keyword = /\\Proxifier\.lnk/ nocase ascii wide
                        $string12_Proxifier_greyware_tool_keyword = /\\ProxifierDrv\.sys/ nocase ascii wide
                        $string13_Proxifier_greyware_tool_keyword = /\\ProxifierPE\.zip/ nocase ascii wide
                        $string14_Proxifier_greyware_tool_keyword = /\\ProxifierSetup\.exe/ nocase ascii wide
                        $string15_Proxifier_greyware_tool_keyword = /\\ProxifierSetup\.tmp/ nocase ascii wide
                        $string16_Proxifier_greyware_tool_keyword = /\\ProxifierShellExt\.dll/ nocase ascii wide
                        $string17_Proxifier_greyware_tool_keyword = /\\ProxyChecker\.exe/ nocase ascii wide
                        $string18_Proxifier_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\Microsoft\\Tracing\\Proxifier_/ nocase ascii wide
                        $string19_Proxifier_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Proxifier/ nocase ascii wide
                        $string20_Proxifier_greyware_tool_keyword = ">Proxifier Setup<" nocase ascii wide
                        $string21_Proxifier_greyware_tool_keyword = /com\.initex\.proxifier\.v3\.macos/ nocase ascii wide
                        $string22_Proxifier_greyware_tool_keyword = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierMac/ nocase ascii wide
                        $string23_Proxifier_greyware_tool_keyword = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierPortable/ nocase ascii wide
                        $string24_Proxifier_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Proxifier/ nocase ascii wide

    condition:
        any of them
}