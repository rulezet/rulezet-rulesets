rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Stowaway/ nocase ascii wide

    condition:
        any of them
}