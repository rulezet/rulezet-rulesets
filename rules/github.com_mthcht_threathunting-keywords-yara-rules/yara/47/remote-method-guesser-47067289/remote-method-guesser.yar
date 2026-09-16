rule remote_method_guesser
{
    meta:
        description = "Detection patterns for the tool 'remote-method-guesser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remote-method-guesser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\senum\s127\.0\.0\.1\s/ nocase ascii wide
                        $string2 = /\/remote\-method\-guesser\.git/ nocase ascii wide
                        $string3 = /\/tmp\/wordlist\.txt/
                        $string4 = /0\.0\.0\.0\:4444/ nocase ascii wide
                        $string5 = /0\.0\.0\.0\:4445/ nocase ascii wide
                        $string6 = /docker\sbuild\s\-t\srmg\s\./ nocase ascii wide
                        $string7 = /jdk.{0,1000}\-activator\-rce\-test\.txt/ nocase ascii wide
                        $string8 = /jdk.{0,1000}\-call\-rce\-test\.txt/ nocase ascii wide
                        $string9 = /jdk.{0,1000}\-dgc\-rce\-test\.txt/ nocase ascii wide
                        $string10 = /jdk.{0,1000}\-method\-rce\-test\.txt/ nocase ascii wide
                        $string11 = /jdk.{0,1000}\-reg\-bypass\.txt/ nocase ascii wide
                        $string12 = "nc -vlp 4444" nocase ascii wide
                        $string13 = "nc -vlp 4445" nocase ascii wide
                        $string14 = "qtc-de/remote-method-guesser" nocase ascii wide
                        $string15 = "remote-method-guesser/rmg" nocase ascii wide
                        $string16 = "remote-method-guesser-master" nocase ascii wide
                        $string17 = /rmg\sbind\s.{0,1000}\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
                        $string18 = /rmg\sbind\s.{0,1000}127\.0\.0\.1\:.{0,1000}\-\-localhost\-bypass/ nocase ascii wide
                        $string19 = /rmg\scall\s.{0,1000}\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
                        $string20 = /rmg\scall\s.{0,1000}\s\-\-signature\s.{0,1000}\s\-\-bound\-name\splain\-server/ nocase ascii wide
                        $string21 = /rmg\scodebase\s.{0,1000}http.{0,1000}\s\-\-component\s/ nocase ascii wide
                        $string22 = /rmg\scodebase\s.{0,1000}java\.util\.HashMap\s.{0,1000}\-\-bound\-name\slegacy\-service/ nocase ascii wide
                        $string23 = "rmg enum " nocase ascii wide
                        $string24 = /rmg\sguess\s.{0,1000}\s/ nocase ascii wide
                        $string25 = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
                        $string26 = /rmg\slisten\s.{0,1000}\sCommonsCollections/ nocase ascii wide
                        $string27 = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
                        $string28 = /rmg\sobjid\s.{0,1000}\[/ nocase ascii wide
                        $string29 = "rmg roguejmx " nocase ascii wide
                        $string30 = "rmg scan " nocase ascii wide
                        $string31 = /rmg\sscan\s.{0,1000}\s\-\-ports\s/ nocase ascii wide
                        $string32 = /rmg\sserial\s.{0,1000}\sAnTrinh\s.{0,1000}\s\-\-component\s/ nocase ascii wide
                        $string33 = /rmg\sserial\s.{0,1000}CommonsCollections/ nocase ascii wide
                        $string34 = /rmg\-.{0,1000}\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string35 = /rmg.{0,1000}\-\-yso/ nocase ascii wide
                        $string36 = "--ssrf --gopher --encode --scan-action filter-bypass" nocase ascii wide
                        $string37 = /wordlists.{0,1000}rmg\.txt/ nocase ascii wide
                        $string38 = /wordlists.{0,1000}rmiscout\.txt/ nocase ascii wide

    condition:
        any of them
}