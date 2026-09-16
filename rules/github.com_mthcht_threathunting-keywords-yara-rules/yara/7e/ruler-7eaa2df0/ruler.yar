rule ruler
{
    meta:
        description = "Detection patterns for the tool 'ruler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBruteForce\(/ nocase ascii wide
                        $string2 = " --insecure brute --userpass " nocase ascii wide
                        $string3 = " --insecure brute --users " nocase ascii wide
                        $string4 = /\sropbuffers\.go/ nocase ascii wide
                        $string5 = /\sruler\.exe/ nocase ascii wide
                        $string6 = "\"WorkstationName\">RULER</Data>" nocase ascii wide
                        $string7 = "/http-ntlm/ntlmtransport" nocase ascii wide
                        $string8 = /\/ntlmtransport\.go/ nocase ascii wide
                        $string9 = /\/ropbuffers\.go/ nocase ascii wide
                        $string10 = "/ruler --domain " nocase ascii wide
                        $string11 = "/ruler --email " nocase ascii wide
                        $string12 = "/ruler --url" nocase ascii wide
                        $string13 = /\/rulerforms\.go/ nocase ascii wide
                        $string14 = /\\autodiscover\\brute\.go/ nocase ascii wide
                        $string15 = /\\ruler\.exe/ nocase ascii wide
                        $string16 = "021ae50ec89266dabb1f96f703ec04dad908eef0e63d12c1ed38a40833198f79" nocase ascii wide
                        $string17 = "42e504f3d9d9800c1c75ff6d8c5433d801e7148760cba709fa3bd5dd8e4a0208" nocase ascii wide
                        $string18 = "904b042e2ec7aa85331911b1343213292e061dcc4f2010d01f4f7b60f0198b10" nocase ascii wide
                        $string19 = "9567021fc5536372a9fb4eea5594d2665e676e88444cd2a017027513662fff18" nocase ascii wide
                        $string20 = /autodiscover\/brute\.go/ nocase ascii wide
                        $string21 = /CreateStringPayload\(\\"RULER\\"\)/ nocase ascii wide
                        $string22 = "f3b5e0f54f1da134c5d3c135f5be8ae7e85e499e8e73fabf87ffe010c23749ef" nocase ascii wide
                        $string23 = "f3e108c7993b8d46c832ac2499a97395cc18fc9c4c1656acc25c969c7090ffcd" nocase ascii wide
                        $string24 = /http\:\/\/212\.111\.43\.206\:9090\/pk\.html/ nocase ascii wide
                        $string25 = "ruler --insecure " nocase ascii wide
                        $string26 = "ruler-linux64"
                        $string27 = "ruler-linux86"
                        $string28 = "ruler-osx64" nocase ascii wide
                        $string29 = /ruler\-win64\.exe/ nocase ascii wide
                        $string30 = /ruler\-win86\.exe/ nocase ascii wide
                        $string31 = "sensepost/ruler" nocase ascii wide
                        $string32 = "UserPassBruteForce" nocase ascii wide

    condition:
        any of them
}