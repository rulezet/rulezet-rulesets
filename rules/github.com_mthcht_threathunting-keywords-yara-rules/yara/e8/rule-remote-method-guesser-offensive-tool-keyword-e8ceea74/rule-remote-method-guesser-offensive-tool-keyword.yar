rule rule_remote_method_guesser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'remote-method-guesser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remote-method-guesser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_remote_method_guesser_offensive_tool_keyword = /\senum\s127\.0\.0\.1\s/ nocase ascii wide
                        $string2_remote_method_guesser_offensive_tool_keyword = /\/remote\-method\-guesser\.git/ nocase ascii wide
                        $string3_remote_method_guesser_offensive_tool_keyword = /\/tmp\/wordlist\.txt/
                        $string4_remote_method_guesser_offensive_tool_keyword = /0\.0\.0\.0\:4444/ nocase ascii wide
                        $string5_remote_method_guesser_offensive_tool_keyword = /0\.0\.0\.0\:4445/ nocase ascii wide
                        $string6_remote_method_guesser_offensive_tool_keyword = /docker\sbuild\s\-t\srmg\s\./ nocase ascii wide
                        $string7_remote_method_guesser_offensive_tool_keyword = /jdk.{0,1000}\-activator\-rce\-test\.txt/ nocase ascii wide
                        $string8_remote_method_guesser_offensive_tool_keyword = /jdk.{0,1000}\-call\-rce\-test\.txt/ nocase ascii wide
                        $string9_remote_method_guesser_offensive_tool_keyword = /jdk.{0,1000}\-dgc\-rce\-test\.txt/ nocase ascii wide
                        $string10_remote_method_guesser_offensive_tool_keyword = /jdk.{0,1000}\-method\-rce\-test\.txt/ nocase ascii wide
                        $string11_remote_method_guesser_offensive_tool_keyword = /jdk.{0,1000}\-reg\-bypass\.txt/ nocase ascii wide
                        $string12_remote_method_guesser_offensive_tool_keyword = "nc -vlp 4444" nocase ascii wide
                        $string13_remote_method_guesser_offensive_tool_keyword = "nc -vlp 4445" nocase ascii wide
                        $string14_remote_method_guesser_offensive_tool_keyword = "qtc-de/remote-method-guesser" nocase ascii wide
                        $string15_remote_method_guesser_offensive_tool_keyword = "remote-method-guesser/rmg" nocase ascii wide
                        $string16_remote_method_guesser_offensive_tool_keyword = "remote-method-guesser-master" nocase ascii wide
                        $string17_remote_method_guesser_offensive_tool_keyword = /rmg\sbind\s.{0,1000}\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
                        $string18_remote_method_guesser_offensive_tool_keyword = /rmg\sbind\s.{0,1000}127\.0\.0\.1\:.{0,1000}\-\-localhost\-bypass/ nocase ascii wide
                        $string19_remote_method_guesser_offensive_tool_keyword = /rmg\scall\s.{0,1000}\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
                        $string20_remote_method_guesser_offensive_tool_keyword = /rmg\scall\s.{0,1000}\s\-\-signature\s.{0,1000}\s\-\-bound\-name\splain\-server/ nocase ascii wide
                        $string21_remote_method_guesser_offensive_tool_keyword = /rmg\scodebase\s.{0,1000}http.{0,1000}\s\-\-component\s/ nocase ascii wide
                        $string22_remote_method_guesser_offensive_tool_keyword = /rmg\scodebase\s.{0,1000}java\.util\.HashMap\s.{0,1000}\-\-bound\-name\slegacy\-service/ nocase ascii wide
                        $string23_remote_method_guesser_offensive_tool_keyword = "rmg enum " nocase ascii wide
                        $string24_remote_method_guesser_offensive_tool_keyword = /rmg\sguess\s.{0,1000}\s/ nocase ascii wide
                        $string25_remote_method_guesser_offensive_tool_keyword = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
                        $string26_remote_method_guesser_offensive_tool_keyword = /rmg\slisten\s.{0,1000}\sCommonsCollections/ nocase ascii wide
                        $string27_remote_method_guesser_offensive_tool_keyword = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
                        $string28_remote_method_guesser_offensive_tool_keyword = /rmg\sobjid\s.{0,1000}\[/ nocase ascii wide
                        $string29_remote_method_guesser_offensive_tool_keyword = "rmg roguejmx " nocase ascii wide
                        $string30_remote_method_guesser_offensive_tool_keyword = "rmg scan " nocase ascii wide
                        $string31_remote_method_guesser_offensive_tool_keyword = /rmg\sscan\s.{0,1000}\s\-\-ports\s/ nocase ascii wide
                        $string32_remote_method_guesser_offensive_tool_keyword = /rmg\sserial\s.{0,1000}\sAnTrinh\s.{0,1000}\s\-\-component\s/ nocase ascii wide
                        $string33_remote_method_guesser_offensive_tool_keyword = /rmg\sserial\s.{0,1000}CommonsCollections/ nocase ascii wide
                        $string34_remote_method_guesser_offensive_tool_keyword = /rmg\-.{0,1000}\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string35_remote_method_guesser_offensive_tool_keyword = /rmg.{0,1000}\-\-yso/ nocase ascii wide
                        $string36_remote_method_guesser_offensive_tool_keyword = "--ssrf --gopher --encode --scan-action filter-bypass" nocase ascii wide
                        $string37_remote_method_guesser_offensive_tool_keyword = /wordlists.{0,1000}rmg\.txt/ nocase ascii wide
                        $string38_remote_method_guesser_offensive_tool_keyword = /wordlists.{0,1000}rmiscout\.txt/ nocase ascii wide

    condition:
        any of them
}