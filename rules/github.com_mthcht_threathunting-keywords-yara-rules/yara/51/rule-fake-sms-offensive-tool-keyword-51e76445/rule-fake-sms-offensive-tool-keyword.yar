rule rule_fake_sms_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fake-sms' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fake-sms"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fake_sms_offensive_tool_keyword = /\.\/fake\-sms/
                        $string2_fake_sms_offensive_tool_keyword = "/bin/fake-sms"
                        $string3_fake_sms_offensive_tool_keyword = /\/fake\-sms\.git/ nocase ascii wide
                        $string4_fake_sms_offensive_tool_keyword = "fake-sms-main" nocase ascii wide
                        $string5_fake_sms_offensive_tool_keyword = "Narasimha1997/fake-sms" nocase ascii wide

    condition:
        any of them
}