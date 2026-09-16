rule rule_PKINITtools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PKINITtools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PKINITtools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PKINITtools_offensive_tool_keyword = /\/httpattack\.py/ nocase ascii wide
                        $string2_PKINITtools_offensive_tool_keyword = "/ntlmrelayx/" nocase ascii wide
                        $string3_PKINITtools_offensive_tool_keyword = "/PKINITtools" nocase ascii wide
                        $string4_PKINITtools_offensive_tool_keyword = /\=Administrator\.ccache/ nocase ascii wide
                        $string5_PKINITtools_offensive_tool_keyword = "dirkjanm/PKINITtools" nocase ascii wide
                        $string6_PKINITtools_offensive_tool_keyword = /export\sKRB5CCNAME\=.{0,1000}\.ccache/ nocase ascii wide
                        $string7_PKINITtools_offensive_tool_keyword = /getnthash\.py/ nocase ascii wide
                        $string8_PKINITtools_offensive_tool_keyword = /gets4uticket\.py/ nocase ascii wide
                        $string9_PKINITtools_offensive_tool_keyword = /gettgtpkinit\.py/ nocase ascii wide
                        $string10_PKINITtools_offensive_tool_keyword = "impacket minikerberos" nocase ascii wide
                        $string11_PKINITtools_offensive_tool_keyword = /PKINITtools\.git/ nocase ascii wide

    condition:
        any of them
}