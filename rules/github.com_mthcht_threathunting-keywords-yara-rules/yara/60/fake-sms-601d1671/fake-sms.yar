rule fake_sms
{
    meta:
        description = "Detection patterns for the tool 'fake-sms' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fake-sms"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/fake\-sms/
                        $string2 = "/bin/fake-sms"
                        $string3 = /\/fake\-sms\.git/ nocase ascii wide
                        $string4 = "fake-sms-main" nocase ascii wide
                        $string5 = "Narasimha1997/fake-sms" nocase ascii wide

    condition:
        any of them
}