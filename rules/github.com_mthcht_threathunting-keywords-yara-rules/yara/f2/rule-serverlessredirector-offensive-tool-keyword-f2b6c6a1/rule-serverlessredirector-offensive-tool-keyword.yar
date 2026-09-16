rule rule_ServerlessRedirector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ServerlessRedirector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ServerlessRedirector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ServerlessRedirector_offensive_tool_keyword = /\/ServerlessRedirector\.git/ nocase ascii wide
                        $string2_ServerlessRedirector_offensive_tool_keyword = "C2FunctionAgent" nocase ascii wide
                        $string3_ServerlessRedirector_offensive_tool_keyword = "https://C2_SERVER_IP/" nocase ascii wide
                        $string4_ServerlessRedirector_offensive_tool_keyword = "KINGSABRI/ServerlessRedirector" nocase ascii wide
                        $string5_ServerlessRedirector_offensive_tool_keyword = "ServerlessRedirector-main" nocase ascii wide

    condition:
        any of them
}