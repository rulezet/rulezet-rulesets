rule linuxprivchecker
{
    meta:
        description = "Detection patterns for the tool 'linuxprivchecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linuxprivchecker"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\:Python\/Empire\.C\!MTB/

    condition:
        any of them
}