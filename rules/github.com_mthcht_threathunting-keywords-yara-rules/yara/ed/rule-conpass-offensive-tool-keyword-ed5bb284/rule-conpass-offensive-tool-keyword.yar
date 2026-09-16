rule rule_conpass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'conpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conpass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_conpass_offensive_tool_keyword = "b09a40f998e8bc112841842ed56d8e843e5df98f4b53657098924fd10325a4b9" nocase ascii wide
                        $string2_conpass_offensive_tool_keyword = /conpass\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string3_conpass_offensive_tool_keyword = /conpass\sv.{0,1000}\s\-\sContinuous\spassword\sspraying\stool/ nocase ascii wide
                        $string4_conpass_offensive_tool_keyword = /DumpNTLMInfo\.py/ nocase ascii wide
                        $string5_conpass_offensive_tool_keyword = "ed99b1d4757d0848ced6b91f18326c42127f6f79ad1cc7e7fafeee91388004e3" nocase ascii wide
                        $string6_conpass_offensive_tool_keyword = /from\sconpass\.ntlminfo\simport\s/ nocase ascii wide
                        $string7_conpass_offensive_tool_keyword = /from\sconpass\.password\simport\s/ nocase ascii wide
                        $string8_conpass_offensive_tool_keyword = "Hackndo/conpass" nocase ascii wide
                        $string9_conpass_offensive_tool_keyword = /impacket\.smbconnection/ nocase ascii wide
                        $string10_conpass_offensive_tool_keyword = "login-securite/conpass" nocase ascii wide
                        $string11_conpass_offensive_tool_keyword = "pip install conpass" nocase ascii wide
                        $string12_conpass_offensive_tool_keyword = /Romain\sBentz\s\(pixis\s\-\s\@hackanddo\)/ nocase ascii wide

    condition:
        any of them
}