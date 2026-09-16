rule rule_antSword_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'antSword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "antSword"
        rule_category = "signature_keyword"

    strings:
                        $string1_antSword_signature_keyword = /Backdoor\.ASP\.WebShell\.ez/ nocase ascii wide
                        $string2_antSword_signature_keyword = /Backdoor\.ASP\.WEBSHELL\.THFBIBC/ nocase ascii wide
                        $string3_antSword_signature_keyword = /Backdoor\:ASP\/Dirtelti\.HA/ nocase ascii wide

    condition:
        any of them
}