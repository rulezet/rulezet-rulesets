rule Python_Rootkit
{
    meta:
        description = "Detection patterns for the tool 'Python-Rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Python-Rootkit"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\:Python\/LaZagne\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}