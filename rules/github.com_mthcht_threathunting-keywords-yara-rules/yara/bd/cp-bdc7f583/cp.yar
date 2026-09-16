rule cp
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:Linux/CopyBashtoTemp" nocase ascii wide

    condition:
        any of them
}