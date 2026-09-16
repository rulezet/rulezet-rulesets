rule gpp_decrypt
{
    meta:
        description = "Detection patterns for the tool 'gpp-decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gpp-decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/gpp-decrypt" nocase ascii wide
                        $string2 = "apt install gpp-decrypt" nocase ascii wide
                        $string3 = "gpp-decrypt " nocase ascii wide
                        $string4 = /gpp\-decrypt\.rb/ nocase ascii wide

    condition:
        any of them
}