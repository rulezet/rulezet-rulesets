rule Proxifier
{
    meta:
        description = "Detection patterns for the tool 'Proxifier' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxifier"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " stop ProxifierDrv" nocase ascii wide
                        $string2 = /\/Proxifier\.app\/Contents\/MacOS\/Proxifier/ nocase ascii wide
                        $string3 = /\/Proxifier\.exe/ nocase ascii wide
                        $string4 = /\/Proxifier\/Proxifier\.app\// nocase ascii wide
                        $string5 = /\/ProxifierPE\.zip/ nocase ascii wide
                        $string6 = /\/ProxifierSetup\.exe/ nocase ascii wide
                        $string7 = /\\AppData\\Local\\Temp\\.{0,1000}\\Proxifier\sPE\\/ nocase ascii wide
                        $string8 = /\\AppData\\Local\\Temp\\Proxifier\sPE\\/ nocase ascii wide
                        $string9 = /\\Proxifier\sService\sManager\.lnk/ nocase ascii wide
                        $string10 = /\\Proxifier\.exe/ nocase ascii wide
                        $string11 = /\\Proxifier\.lnk/ nocase ascii wide
                        $string12 = /\\ProxifierDrv\.sys/ nocase ascii wide
                        $string13 = /\\ProxifierPE\.zip/ nocase ascii wide
                        $string14 = /\\ProxifierSetup\.exe/ nocase ascii wide
                        $string15 = /\\ProxifierSetup\.tmp/ nocase ascii wide
                        $string16 = /\\ProxifierShellExt\.dll/ nocase ascii wide
                        $string17 = /\\ProxyChecker\.exe/ nocase ascii wide
                        $string18 = /\\SOFTWARE\\WOW6432Node\\Microsoft\\Tracing\\Proxifier_/ nocase ascii wide
                        $string19 = /\\Start\sMenu\\Programs\\Proxifier/ nocase ascii wide
                        $string20 = ">Proxifier Setup<" nocase ascii wide
                        $string21 = /com\.initex\.proxifier\.v3\.macos/ nocase ascii wide
                        $string22 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierMac/ nocase ascii wide
                        $string23 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierPortable/ nocase ascii wide
                        $string24 = /Program\sFiles\s\(x86\)\\Proxifier/ nocase ascii wide

    condition:
        any of them
}