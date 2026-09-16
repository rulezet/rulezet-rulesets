rule AzureC2Relay
{
    meta:
        description = "Detection patterns for the tool 'AzureC2Relay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureC2Relay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/AzureC2Relay" nocase ascii wide
                        $string2 = /\/ParsedMalleableData\.txt/ nocase ascii wide
                        $string3 = /\\AzureC2Proxy\\/ nocase ascii wide
                        $string4 = /\\AzureC2Relay/ nocase ascii wide
                        $string5 = /\\ParsedMalleableData\.txt/ nocase ascii wide
                        $string6 = /AzureC2Relay\.zip/ nocase ascii wide
                        $string7 = "AzureC2Relay-main" nocase ascii wide
                        $string8 = /cobaltstrike\-dist\.tgz/ nocase ascii wide
                        $string9 = /dotnet\sParseMalleable\/ParseMalleable\.dll/ nocase ascii wide
                        $string10 = /GenericC2Relay\.cs/ nocase ascii wide
                        $string11 = "MalleableProfileB64" nocase ascii wide
                        $string12 = /mojo\.5688\.8052\.183894939787088877\#\#/ nocase ascii wide
                        $string13 = /mojo\.5688\.8052\.35780273329370473\#\#/ nocase ascii wide

    condition:
        any of them
}