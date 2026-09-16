rule rule_MailPassView_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "signature_keyword"

    strings:
                        $string1_MailPassView_signature_keyword = "HackTool:Win32/Passview!MTB" nocase ascii wide

    condition:
        any of them
}