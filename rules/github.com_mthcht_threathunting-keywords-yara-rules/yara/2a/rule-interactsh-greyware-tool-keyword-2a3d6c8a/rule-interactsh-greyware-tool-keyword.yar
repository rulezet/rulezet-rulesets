rule rule_interactsh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'interactsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "interactsh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_interactsh_greyware_tool_keyword = /\.exec.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string2_interactsh_greyware_tool_keyword = /\.interactsh\.com/ nocase ascii wide
                        $string3_interactsh_greyware_tool_keyword = "/interactsh/" nocase ascii wide
                        $string4_interactsh_greyware_tool_keyword = "/interactsh-client" nocase ascii wide
                        $string5_interactsh_greyware_tool_keyword = "/interactsh-collaborator" nocase ascii wide
                        $string6_interactsh_greyware_tool_keyword = "/interactsh-server" nocase ascii wide
                        $string7_interactsh_greyware_tool_keyword = /curl.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string8_interactsh_greyware_tool_keyword = /http\:\/\/.{0,1000}\.interact\.sh/ nocase ascii wide
                        $string9_interactsh_greyware_tool_keyword = "interactsh -" nocase ascii wide
                        $string10_interactsh_greyware_tool_keyword = /interactsh.{0,1000}\.exe/ nocase ascii wide
                        $string11_interactsh_greyware_tool_keyword = /interactsh.{0,1000}oast\./ nocase ascii wide
                        $string12_interactsh_greyware_tool_keyword = "interactsh-client -" nocase ascii wide
                        $string13_interactsh_greyware_tool_keyword = "interactsh-server -" nocase ascii wide
                        $string14_interactsh_greyware_tool_keyword = "projectdiscovery/interactsh" nocase ascii wide
                        $string15_interactsh_greyware_tool_keyword = /wget.{0,1000}\.interact\.sh/ nocase ascii wide

    condition:
        any of them
}