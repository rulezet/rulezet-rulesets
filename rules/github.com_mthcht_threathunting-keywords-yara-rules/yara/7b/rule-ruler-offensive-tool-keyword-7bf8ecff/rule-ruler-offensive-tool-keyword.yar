rule rule_ruler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ruler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ruler_offensive_tool_keyword = /\sBruteForce\(/ nocase ascii wide
                        $string2_ruler_offensive_tool_keyword = " --insecure brute --userpass " nocase ascii wide
                        $string3_ruler_offensive_tool_keyword = " --insecure brute --users " nocase ascii wide
                        $string4_ruler_offensive_tool_keyword = /\sropbuffers\.go/ nocase ascii wide
                        $string5_ruler_offensive_tool_keyword = /\sruler\.exe/ nocase ascii wide
                        $string6_ruler_offensive_tool_keyword = "\"WorkstationName\">RULER</Data>" nocase ascii wide
                        $string7_ruler_offensive_tool_keyword = "/http-ntlm/ntlmtransport" nocase ascii wide
                        $string8_ruler_offensive_tool_keyword = /\/ntlmtransport\.go/ nocase ascii wide
                        $string9_ruler_offensive_tool_keyword = /\/ropbuffers\.go/ nocase ascii wide
                        $string10_ruler_offensive_tool_keyword = "/ruler --domain " nocase ascii wide
                        $string11_ruler_offensive_tool_keyword = "/ruler --email " nocase ascii wide
                        $string12_ruler_offensive_tool_keyword = "/ruler --url" nocase ascii wide
                        $string13_ruler_offensive_tool_keyword = /\/rulerforms\.go/ nocase ascii wide
                        $string14_ruler_offensive_tool_keyword = /\\autodiscover\\brute\.go/ nocase ascii wide
                        $string15_ruler_offensive_tool_keyword = /\\ruler\.exe/ nocase ascii wide
                        $string16_ruler_offensive_tool_keyword = "021ae50ec89266dabb1f96f703ec04dad908eef0e63d12c1ed38a40833198f79" nocase ascii wide
                        $string17_ruler_offensive_tool_keyword = "42e504f3d9d9800c1c75ff6d8c5433d801e7148760cba709fa3bd5dd8e4a0208" nocase ascii wide
                        $string18_ruler_offensive_tool_keyword = "904b042e2ec7aa85331911b1343213292e061dcc4f2010d01f4f7b60f0198b10" nocase ascii wide
                        $string19_ruler_offensive_tool_keyword = "9567021fc5536372a9fb4eea5594d2665e676e88444cd2a017027513662fff18" nocase ascii wide
                        $string20_ruler_offensive_tool_keyword = /autodiscover\/brute\.go/ nocase ascii wide
                        $string21_ruler_offensive_tool_keyword = /CreateStringPayload\(\\"RULER\\"\)/ nocase ascii wide
                        $string22_ruler_offensive_tool_keyword = "f3b5e0f54f1da134c5d3c135f5be8ae7e85e499e8e73fabf87ffe010c23749ef" nocase ascii wide
                        $string23_ruler_offensive_tool_keyword = "f3e108c7993b8d46c832ac2499a97395cc18fc9c4c1656acc25c969c7090ffcd" nocase ascii wide
                        $string24_ruler_offensive_tool_keyword = /http\:\/\/212\.111\.43\.206\:9090\/pk\.html/ nocase ascii wide
                        $string25_ruler_offensive_tool_keyword = "ruler --insecure " nocase ascii wide
                        $string26_ruler_offensive_tool_keyword = "ruler-linux64"
                        $string27_ruler_offensive_tool_keyword = "ruler-linux86"
                        $string28_ruler_offensive_tool_keyword = "ruler-osx64" nocase ascii wide
                        $string29_ruler_offensive_tool_keyword = /ruler\-win64\.exe/ nocase ascii wide
                        $string30_ruler_offensive_tool_keyword = /ruler\-win86\.exe/ nocase ascii wide
                        $string31_ruler_offensive_tool_keyword = "sensepost/ruler" nocase ascii wide
                        $string32_ruler_offensive_tool_keyword = "UserPassBruteForce" nocase ascii wide

    condition:
        any of them
}