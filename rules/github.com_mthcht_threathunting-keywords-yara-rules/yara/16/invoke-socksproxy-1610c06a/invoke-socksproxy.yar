rule Invoke_SocksProxy
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Backdoor:Win64/PortStarter" nocase ascii wide
                        $string2 = "Backdoor:Win64/PortStarter" nocase ascii wide

    condition:
        any of them
}