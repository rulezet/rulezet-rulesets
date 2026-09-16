rule disctopia_c2
{
    meta:
        description = "Detection patterns for the tool 'disctopia-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "disctopia-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/disctopia\.py/ nocase ascii wide
                        $string2 = "/disctopia-c2" nocase ascii wide
                        $string3 = "/distopia-test" nocase ascii wide
                        $string4 = "Disctopia Backdoor" nocase ascii wide
                        $string5 = /disctopia\-c2\.git/ nocase ascii wide
                        $string6 = /disctopia\-c2\-main\.zip/ nocase ascii wide
                        $string7 = /keylogger\.py/ nocase ascii wide
                        $string8 = /sandboxevasion\.py/ nocase ascii wide

    condition:
        any of them
}