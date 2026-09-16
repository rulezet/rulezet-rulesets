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
                        $string7_remote_method_guesser_offensive_tool_keyword = /jdk.{0,100}\-activator\-rce\-test\.txt/ nocase ascii wide
                        $string8_remote_method_guesser_offensive_tool_keyword = /jdk.{0,100}\-call\-rce\-test\.txt/ nocase ascii wide
                        $string9_remote_method_guesser_offensive_tool_keyword = /jdk.{0,100}\-dgc\-rce\-test\.txt/ nocase ascii wide
                        $string10_remote_method_guesser_offensive_tool_keyword = /jdk.{0,100}\-method\-rce\-test\.txt/ nocase ascii wide
                        $string11_remote_method_guesser_offensive_tool_keyword = /jdk.{0,100}\-reg\-bypass\.txt/ nocase ascii wide
                        $string12_remote_method_guesser_offensive_tool_keyword = "nc -vlp 4444" nocase ascii wide
                        $string13_remote_method_guesser_offensive_tool_keyword = "nc -vlp 4445" nocase ascii wide
                        $string14_remote_method_guesser_offensive_tool_keyword = "qtc-de/remote-method-guesser" nocase ascii wide
                        $string15_remote_method_guesser_offensive_tool_keyword = "remote-method-guesser/rmg" nocase ascii wide
                        $string16_remote_method_guesser_offensive_tool_keyword = "remote-method-guesser-master" nocase ascii wide
                        $string17_remote_method_guesser_offensive_tool_keyword = /rmg\sbind\s.{0,100}\sjmxrmi\s\-\-bind\-objid\s/ nocase ascii wide
                        $string18_remote_method_guesser_offensive_tool_keyword = /rmg\sbind\s.{0,100}127\.0\.0\.1\:.{0,100}\-\-localhost\-bypass/ nocase ascii wide
                        $string19_remote_method_guesser_offensive_tool_keyword = /rmg\scall\s.{0,100}\s\-\-plugin\sGenericPrint\.jar/ nocase ascii wide
                        $string20_remote_method_guesser_offensive_tool_keyword = /rmg\scall\s.{0,100}\s\-\-signature\s.{0,100}\s\-\-bound\-name\splain\-server/ nocase ascii wide
                        $string21_remote_method_guesser_offensive_tool_keyword = /rmg\scodebase\s.{0,100}http.{0,100}\s\-\-component\s/ nocase ascii wide
                        $string22_remote_method_guesser_offensive_tool_keyword = /rmg\scodebase\s.{0,100}java\.util\.HashMap\s.{0,100}\-\-bound\-name\slegacy\-service/ nocase ascii wide
                        $string23_remote_method_guesser_offensive_tool_keyword = "rmg enum " nocase ascii wide
                        $string24_remote_method_guesser_offensive_tool_keyword = /rmg\sguess\s.{0,100}\s/ nocase ascii wide
                        $string25_remote_method_guesser_offensive_tool_keyword = /rmg\sknown\sjavax\.management\.remote\.rmi\.RMIServerImpl_Stub/ nocase ascii wide
                        $string26_remote_method_guesser_offensive_tool_keyword = /rmg\slisten\s.{0,100}\sCommonsCollections/ nocase ascii wide
                        $string27_remote_method_guesser_offensive_tool_keyword = /rmg\slisten\s0\.0\.0\.0\s/ nocase ascii wide
                        $string28_remote_method_guesser_offensive_tool_keyword = /rmg\sobjid\s.{0,100}\[/ nocase ascii wide
                        $string29_remote_method_guesser_offensive_tool_keyword = "rmg roguejmx " nocase ascii wide
                        $string30_remote_method_guesser_offensive_tool_keyword = "rmg scan " nocase ascii wide
                        $string31_remote_method_guesser_offensive_tool_keyword = /rmg\sscan\s.{0,100}\s\-\-ports\s/ nocase ascii wide
                        $string32_remote_method_guesser_offensive_tool_keyword = /rmg\sserial\s.{0,100}\sAnTrinh\s.{0,100}\s\-\-component\s/ nocase ascii wide
                        $string33_remote_method_guesser_offensive_tool_keyword = /rmg\sserial\s.{0,100}CommonsCollections/ nocase ascii wide
                        $string34_remote_method_guesser_offensive_tool_keyword = /rmg\-.{0,100}\-jar\-with\-dependencies\.jar/ nocase ascii wide
                        $string35_remote_method_guesser_offensive_tool_keyword = /rmg.{0,100}\-\-yso/ nocase ascii wide
                        $string36_remote_method_guesser_offensive_tool_keyword = "--ssrf --gopher --encode --scan-action filter-bypass" nocase ascii wide
                        $string37_remote_method_guesser_offensive_tool_keyword = /wordlists.{0,100}rmg\.txt/ nocase ascii wide
                        $string38_remote_method_guesser_offensive_tool_keyword = /wordlists.{0,100}rmiscout\.txt/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}