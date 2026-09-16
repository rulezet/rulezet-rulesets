rule rule_DPAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DPAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DPAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DPAT_offensive_tool_keyword = /\/dpat\.py/ nocase ascii wide
                        $string2_DPAT_offensive_tool_keyword = /\/ntlmUserPasswords\.ntlm/ nocase ascii wide
                        $string3_DPAT_offensive_tool_keyword = /\\dpat\.py/ nocase ascii wide
                        $string4_DPAT_offensive_tool_keyword = /_DomainPasswordAuditReport\.html/ nocase ascii wide
                        $string5_DPAT_offensive_tool_keyword = "2fe5dc013f99c83e5c353ab5a064ad0ce2f197debb7b03f430934004923f6071" nocase ascii wide
                        $string6_DPAT_offensive_tool_keyword = "clr2of8/DPAT" nocase ascii wide
                        $string7_DPAT_offensive_tool_keyword = /crack_it\(nt_hash\,\slm_pass\)/ nocase ascii wide
                        $string8_DPAT_offensive_tool_keyword = /\-n\sntds\.dit\s\-c\shashcat/ nocase ascii wide
                        $string9_DPAT_offensive_tool_keyword = /users_only_cracked_through_lm\.html/ nocase ascii wide

    condition:
        any of them
}