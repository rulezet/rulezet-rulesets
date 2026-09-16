rule rule_requests_ntlm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'requests-ntlm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requests-ntlm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_requests_ntlm_greyware_tool_keyword = " install requests_ntlm" nocase ascii wide
                        $string2_requests_ntlm_greyware_tool_keyword = "from requests_ntlm import HttpNtlmAuth" nocase ascii wide

    condition:
        any of them
}