rule AnyplaceControl
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "RemoteAccess:Win32/AnyplaceControl" nocase ascii wide

    condition:
        any of them
}