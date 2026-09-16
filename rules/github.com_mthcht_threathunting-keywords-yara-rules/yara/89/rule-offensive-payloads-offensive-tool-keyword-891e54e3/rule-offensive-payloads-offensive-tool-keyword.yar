rule rule_Offensive_Payloads_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Offensive_Payloads_offensive_tool_keyword = "Cross-Site-Scripting-XSS-Payloads" nocase ascii wide
                        $string2_Offensive_Payloads_offensive_tool_keyword = /Directory\-Traversal\-Payloads\./ nocase ascii wide
                        $string3_Offensive_Payloads_offensive_tool_keyword = /File\-Extensions\-Wordlist\.txt/ nocase ascii wide
                        $string4_Offensive_Payloads_offensive_tool_keyword = /Html\-Injection\-Payloads\./ nocase ascii wide
                        $string5_Offensive_Payloads_offensive_tool_keyword = /Html\-Injection\-Read\-File\-Payloads\./ nocase ascii wide
                        $string6_Offensive_Payloads_offensive_tool_keyword = /OS\-Command\-Injection\-Unix\-Payloads\./ nocase ascii wide
                        $string7_Offensive_Payloads_offensive_tool_keyword = /OS\-Command\-Injection\-Windows\-Payloads\./ nocase ascii wide
                        $string8_Offensive_Payloads_offensive_tool_keyword = /PHP\-Code\-injection\./ nocase ascii wide
                        $string9_Offensive_Payloads_offensive_tool_keyword = /PHP\-Code\-Injections\-Payloads\./ nocase ascii wide
                        $string10_Offensive_Payloads_offensive_tool_keyword = /Server\-Side\-Request\-Forgery\-Payloads\./ nocase ascii wide
                        $string11_Offensive_Payloads_offensive_tool_keyword = /SQL\-Injection\-Auth\-Bypass\-Payloads\./ nocase ascii wide
                        $string12_Offensive_Payloads_offensive_tool_keyword = /SQL\-Injection\-Payloads\./ nocase ascii wide
                        $string13_Offensive_Payloads_offensive_tool_keyword = /XML\-External\-Entity\-\(XXE\)\-Payloads/ nocase ascii wide

    condition:
        any of them
}