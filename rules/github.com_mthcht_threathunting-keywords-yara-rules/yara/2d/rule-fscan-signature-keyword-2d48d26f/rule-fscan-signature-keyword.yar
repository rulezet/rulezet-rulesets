rule rule_fscan_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'fscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fscan"
        rule_category = "signature_keyword"

    strings:
                        $string1_fscan_signature_keyword = "HackTool:Linux/Fscan"

    condition:
        any of them
}