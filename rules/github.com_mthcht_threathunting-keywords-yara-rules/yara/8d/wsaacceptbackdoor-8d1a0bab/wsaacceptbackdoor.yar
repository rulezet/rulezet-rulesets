rule WSAAcceptBackdoor
{
    meta:
        description = "Detection patterns for the tool 'WSAAcceptBackdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSAAcceptBackdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/WSAAcceptBackdoor\.git/ nocase ascii wide
                        $string2 = /\\WSAAcceptBackdoor\./ nocase ascii wide
                        $string3 = /\\WSAAcceptBackdoor\-main/ nocase ascii wide
                        $string4 = "16edb60cec97590d754e99e2eb719bbc990d71dcf1bda7c8eebf3b517574846d" nocase ascii wide
                        $string5 = "811683b1-e01c-4ef8-82d1-aa08293d3e7c" nocase ascii wide
                        $string6 = "define BACKDOOR_PORT " nocase ascii wide
                        $string7 = "EgeBalci/WSAAcceptBackdoor" nocase ascii wide
                        $string8 = /WSAAcceptBackdoor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}