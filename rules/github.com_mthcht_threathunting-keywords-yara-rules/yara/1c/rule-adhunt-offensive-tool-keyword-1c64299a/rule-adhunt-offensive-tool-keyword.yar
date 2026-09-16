rule rule_adhunt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adhunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adhunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adhunt_offensive_tool_keyword = /\sadhunt\.py\s/ nocase ascii wide
                        $string2_adhunt_offensive_tool_keyword = /\/ADHunt\.git/ nocase ascii wide
                        $string3_adhunt_offensive_tool_keyword = /\/adhunt\.py/ nocase ascii wide
                        $string4_adhunt_offensive_tool_keyword = /\\adhunt\.py/ nocase ascii wide
                        $string5_adhunt_offensive_tool_keyword = /ad_dns_dump\.txt/ nocase ascii wide
                        $string6_adhunt_offensive_tool_keyword = /ADHunt\-main\.zip/ nocase ascii wide
                        $string7_adhunt_offensive_tool_keyword = /dcenum\.run/ nocase ascii wide
                        $string8_adhunt_offensive_tool_keyword = /delegation_constrained_objects\.txt/ nocase ascii wide
                        $string9_adhunt_offensive_tool_keyword = /delegation_constrained_w_protocol_transition_objects\.txt/ nocase ascii wide
                        $string10_adhunt_offensive_tool_keyword = /delegation_rbcd_objects\.txt/ nocase ascii wide
                        $string11_adhunt_offensive_tool_keyword = /delegation_unconstrained_objects\.txt/ nocase ascii wide
                        $string12_adhunt_offensive_tool_keyword = "karendm/ADHunt" nocase ascii wide
                        $string13_adhunt_offensive_tool_keyword = /objects_constrained_delegation_full\.txt/ nocase ascii wide
                        $string14_adhunt_offensive_tool_keyword = /objects_rbcd_delegation_full\.txt/ nocase ascii wide
                        $string15_adhunt_offensive_tool_keyword = /objects_unconstrained_delegation_full\.txt/ nocase ascii wide
                        $string16_adhunt_offensive_tool_keyword = /smbenum\.run/ nocase ascii wide
                        $string17_adhunt_offensive_tool_keyword = /users_asreproast\.txt/ nocase ascii wide
                        $string18_adhunt_offensive_tool_keyword = /users_dcsrp_full\.txt/ nocase ascii wide
                        $string19_adhunt_offensive_tool_keyword = /users_kerberoasting\.txt/ nocase ascii wide
                        $string20_adhunt_offensive_tool_keyword = /users_no_req_pass\.txt/ nocase ascii wide
                        $string21_adhunt_offensive_tool_keyword = /users_no_req_pass_full\.txt/ nocase ascii wide

    condition:
        any of them
}