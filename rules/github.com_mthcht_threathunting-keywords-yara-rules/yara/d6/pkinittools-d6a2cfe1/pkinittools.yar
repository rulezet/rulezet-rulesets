rule PKINITtools
{
    meta:
        description = "Detection patterns for the tool 'PKINITtools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PKINITtools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/httpattack\.py/ nocase ascii wide
                        $string2 = "/ntlmrelayx/" nocase ascii wide
                        $string3 = "/PKINITtools" nocase ascii wide
                        $string4 = /\=Administrator\.ccache/ nocase ascii wide
                        $string5 = "dirkjanm/PKINITtools" nocase ascii wide
                        $string6 = /export\sKRB5CCNAME\=.{0,1000}\.ccache/ nocase ascii wide
                        $string7 = /getnthash\.py/ nocase ascii wide
                        $string8 = /gets4uticket\.py/ nocase ascii wide
                        $string9 = /gettgtpkinit\.py/ nocase ascii wide
                        $string10 = "impacket minikerberos" nocase ascii wide
                        $string11 = /PKINITtools\.git/ nocase ascii wide

    condition:
        any of them
}