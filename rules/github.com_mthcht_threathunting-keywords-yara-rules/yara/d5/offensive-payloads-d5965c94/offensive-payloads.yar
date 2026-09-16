rule Offensive_Payloads
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Cross-Site-Scripting-XSS-Payloads" nocase ascii wide
                        $string2 = /Directory\-Traversal\-Payloads\./ nocase ascii wide
                        $string3 = /File\-Extensions\-Wordlist\.txt/ nocase ascii wide
                        $string4 = /Html\-Injection\-Payloads\./ nocase ascii wide
                        $string5 = /Html\-Injection\-Read\-File\-Payloads\./ nocase ascii wide
                        $string6 = /OS\-Command\-Injection\-Unix\-Payloads\./ nocase ascii wide
                        $string7 = /OS\-Command\-Injection\-Windows\-Payloads\./ nocase ascii wide
                        $string8 = /PHP\-Code\-injection\./ nocase ascii wide
                        $string9 = /PHP\-Code\-Injections\-Payloads\./ nocase ascii wide
                        $string10 = /Server\-Side\-Request\-Forgery\-Payloads\./ nocase ascii wide
                        $string11 = /SQL\-Injection\-Auth\-Bypass\-Payloads\./ nocase ascii wide
                        $string12 = /SQL\-Injection\-Payloads\./ nocase ascii wide
                        $string13 = /XML\-External\-Entity\-\(XXE\)\-Payloads/ nocase ascii wide

    condition:
        any of them
}