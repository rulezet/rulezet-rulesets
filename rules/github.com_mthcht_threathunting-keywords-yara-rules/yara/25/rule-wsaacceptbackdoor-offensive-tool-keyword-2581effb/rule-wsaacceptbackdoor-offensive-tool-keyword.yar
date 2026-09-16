rule rule_WSAAcceptBackdoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WSAAcceptBackdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSAAcceptBackdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WSAAcceptBackdoor_offensive_tool_keyword = /\/WSAAcceptBackdoor\.git/ nocase ascii wide
                        $string2_WSAAcceptBackdoor_offensive_tool_keyword = /\\WSAAcceptBackdoor\./ nocase ascii wide
                        $string3_WSAAcceptBackdoor_offensive_tool_keyword = /\\WSAAcceptBackdoor\-main/ nocase ascii wide
                        $string4_WSAAcceptBackdoor_offensive_tool_keyword = "16edb60cec97590d754e99e2eb719bbc990d71dcf1bda7c8eebf3b517574846d" nocase ascii wide
                        $string5_WSAAcceptBackdoor_offensive_tool_keyword = "811683b1-e01c-4ef8-82d1-aa08293d3e7c" nocase ascii wide
                        $string6_WSAAcceptBackdoor_offensive_tool_keyword = "define BACKDOOR_PORT " nocase ascii wide
                        $string7_WSAAcceptBackdoor_offensive_tool_keyword = "EgeBalci/WSAAcceptBackdoor" nocase ascii wide
                        $string8_WSAAcceptBackdoor_offensive_tool_keyword = /WSAAcceptBackdoor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}