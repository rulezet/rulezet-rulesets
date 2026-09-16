rule interactsh
{
    meta:
        description = "Detection patterns for the tool 'interactsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "interactsh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.exec.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string2 = /\.interactsh\.com/ nocase ascii wide
                        $string3 = "/interactsh/" nocase ascii wide
                        $string4 = "/interactsh-client" nocase ascii wide
                        $string5 = "/interactsh-collaborator" nocase ascii wide
                        $string6 = "/interactsh-server" nocase ascii wide
                        $string7 = /curl.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string8 = /http\:\/\/.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string9 = "interactsh -" nocase ascii wide
                        $string10 = /interactsh.{0,1000}\.exe/ nocase ascii wide
                        $string11 = /interactsh.{0,1000}oast\./ nocase ascii wide
                        $string12 = "interactsh-client -" nocase ascii wide
                        $string13 = "interactsh-server -" nocase ascii wide
                        $string14 = "projectdiscovery/interactsh" nocase ascii wide
                        $string15 = /wget.{0,1000}\.interact\.sh/ nocase ascii wide

    condition:
        any of them
}