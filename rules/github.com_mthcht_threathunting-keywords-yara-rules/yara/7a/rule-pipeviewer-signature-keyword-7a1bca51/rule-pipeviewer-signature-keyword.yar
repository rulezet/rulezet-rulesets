rule rule_PipeViewer__signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'PipeViewer ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PipeViewer "
        rule_category = "signature_keyword"

    strings:
                        $string1_PipeViewer__signature_keyword = "Trojan:Win32/Malagent!MSR" nocase ascii wide

    condition:
        any of them
}