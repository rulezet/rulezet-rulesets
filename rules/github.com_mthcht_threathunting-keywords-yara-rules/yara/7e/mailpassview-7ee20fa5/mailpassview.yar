rule MailPassView
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:Win32/Passview!MTB" nocase ascii wide

    condition:
        any of them
}