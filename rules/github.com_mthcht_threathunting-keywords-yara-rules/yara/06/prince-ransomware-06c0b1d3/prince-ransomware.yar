rule Prince_Ransomware
{
    meta:
        description = "Detection patterns for the tool 'Prince-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Prince-Ransomware"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Ransom\:Win64\/PrinceRansom\.YAA\!MTB/ nocase ascii wide

    condition:
        any of them
}