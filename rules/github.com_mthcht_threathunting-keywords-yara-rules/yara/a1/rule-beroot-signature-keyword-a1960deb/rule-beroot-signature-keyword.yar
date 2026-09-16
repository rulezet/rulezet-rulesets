rule rule_BeRoot_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "signature_keyword"

    strings:
                        $string1_BeRoot_signature_keyword = "HackTool:SH/LinuxExploitSuggest"

    condition:
        any of them
}