rule BeRoot
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:SH/LinuxExploitSuggest"

    condition:
        any of them
}