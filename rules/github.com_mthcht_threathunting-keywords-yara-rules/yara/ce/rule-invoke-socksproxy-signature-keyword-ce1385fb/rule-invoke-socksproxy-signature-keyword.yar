rule rule_Invoke_SocksProxy_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "signature_keyword"

    strings:
                        $string1_Invoke_SocksProxy_signature_keyword = "Backdoor:Win64/PortStarter" nocase ascii wide
                        $string2_Invoke_SocksProxy_signature_keyword = "Backdoor:Win64/PortStarter" nocase ascii wide

    condition:
        any of them
}