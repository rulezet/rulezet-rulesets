rule antSword
{
    meta:
        description = "Detection patterns for the tool 'antSword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "antSword"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Backdoor\.ASP\.WebShell\.ez/ nocase ascii wide
                        $string2 = /Backdoor\.ASP\.WEBSHELL\.THFBIBC/ nocase ascii wide
                        $string3 = /Backdoor\:ASP\/Dirtelti\.HA/ nocase ascii wide

    condition:
        any of them
}