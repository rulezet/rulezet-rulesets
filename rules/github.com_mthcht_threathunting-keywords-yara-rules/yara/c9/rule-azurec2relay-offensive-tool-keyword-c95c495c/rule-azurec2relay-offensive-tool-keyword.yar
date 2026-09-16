rule rule_AzureC2Relay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AzureC2Relay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureC2Relay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AzureC2Relay_offensive_tool_keyword = "/AzureC2Relay" nocase ascii wide
                        $string2_AzureC2Relay_offensive_tool_keyword = /\/ParsedMalleableData\.txt/ nocase ascii wide
                        $string3_AzureC2Relay_offensive_tool_keyword = /\\AzureC2Proxy\\/ nocase ascii wide
                        $string4_AzureC2Relay_offensive_tool_keyword = /\\AzureC2Relay/ nocase ascii wide
                        $string5_AzureC2Relay_offensive_tool_keyword = /\\ParsedMalleableData\.txt/ nocase ascii wide
                        $string6_AzureC2Relay_offensive_tool_keyword = /AzureC2Relay\.zip/ nocase ascii wide
                        $string7_AzureC2Relay_offensive_tool_keyword = "AzureC2Relay-main" nocase ascii wide
                        $string8_AzureC2Relay_offensive_tool_keyword = /cobaltstrike\-dist\.tgz/ nocase ascii wide
                        $string9_AzureC2Relay_offensive_tool_keyword = /dotnet\sParseMalleable\/ParseMalleable\.dll/ nocase ascii wide
                        $string10_AzureC2Relay_offensive_tool_keyword = /GenericC2Relay\.cs/ nocase ascii wide
                        $string11_AzureC2Relay_offensive_tool_keyword = "MalleableProfileB64" nocase ascii wide
                        $string12_AzureC2Relay_offensive_tool_keyword = /mojo\.5688\.8052\.183894939787088877\#\#/ nocase ascii wide
                        $string13_AzureC2Relay_offensive_tool_keyword = /mojo\.5688\.8052\.35780273329370473\#\#/ nocase ascii wide

    condition:
        any of them
}