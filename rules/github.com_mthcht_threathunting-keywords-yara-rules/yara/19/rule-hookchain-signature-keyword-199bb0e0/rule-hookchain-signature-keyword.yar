rule rule_hookchain_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'hookchain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hookchain"
        rule_category = "signature_keyword"

    strings:
                        $string1_hookchain_signature_keyword = /Generic\.HookChain\.A\.88E059A3/ nocase ascii wide

    condition:
        any of them
}