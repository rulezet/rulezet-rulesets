rule rule_stowaway_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "signature_keyword"

    strings:
                        $string1_stowaway_signature_keyword = /HackTool\.Stowaway/ nocase ascii wide

    condition:
        any of them
}