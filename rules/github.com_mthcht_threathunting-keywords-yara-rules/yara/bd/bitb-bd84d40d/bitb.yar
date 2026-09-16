rule bitb
{
    meta:
        description = "Detection patterns for the tool 'bitb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BITB\.git/ nocase ascii wide
                        $string2 = "/BITB-main" nocase ascii wide
                        $string3 = /\\BITB\-main/ nocase ascii wide
                        $string4 = /bitb_server\/phishing\.ini/ nocase ascii wide
                        $string5 = "mrd0x/BITB" nocase ascii wide
                        $string6 = "XX-PHISHING-LINK-XX" nocase ascii wide

    condition:
        any of them
}