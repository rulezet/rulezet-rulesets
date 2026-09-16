rule rule_rpivot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rpivot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rpivot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rpivot_offensive_tool_keyword = /\s\-\-ntlm\-proxy\-ip\s.{0,1000}\s\-\-ntlm\-proxy\-port\s/ nocase ascii wide
                        $string2_rpivot_offensive_tool_keyword = /\/rpivot\.git/ nocase ascii wide
                        $string3_rpivot_offensive_tool_keyword = "9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45" nocase ascii wide
                        $string4_rpivot_offensive_tool_keyword = /client\.py\s\-\-server\-ip\s.{0,1000}\s\-\-server\-port\s/ nocase ascii wide
                        $string5_rpivot_offensive_tool_keyword = /client\.py.{0,1000}\-\-domain.{0,1000}\-\-hashes/ nocase ascii wide
                        $string6_rpivot_offensive_tool_keyword = "klsecservices/rpivot" nocase ascii wide
                        $string7_rpivot_offensive_tool_keyword = /rpivot\.zip/ nocase ascii wide
                        $string8_rpivot_offensive_tool_keyword = "rpivot-master" nocase ascii wide
                        $string9_rpivot_offensive_tool_keyword = /\-\-server\-port\s.{0,1000}\s\-\-server\-ip\s.{0,1000}\s\-\-proxy\-ip\s.{0,1000}\s\-\-proxy\-port\s/ nocase ascii wide

    condition:
        any of them
}