rule adhunt
{
    meta:
        description = "Detection patterns for the tool 'adhunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adhunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadhunt\.py\s/ nocase ascii wide
                        $string2 = /\/ADHunt\.git/ nocase ascii wide
                        $string3 = /\/adhunt\.py/ nocase ascii wide
                        $string4 = /\\adhunt\.py/ nocase ascii wide
                        $string5 = /ad_dns_dump\.txt/ nocase ascii wide
                        $string6 = /ADHunt\-main\.zip/ nocase ascii wide
                        $string7 = /dcenum\.run/ nocase ascii wide
                        $string8 = /delegation_constrained_objects\.txt/ nocase ascii wide
                        $string9 = /delegation_constrained_w_protocol_transition_objects\.txt/ nocase ascii wide
                        $string10 = /delegation_rbcd_objects\.txt/ nocase ascii wide
                        $string11 = /delegation_unconstrained_objects\.txt/ nocase ascii wide
                        $string12 = "karendm/ADHunt" nocase ascii wide
                        $string13 = /objects_constrained_delegation_full\.txt/ nocase ascii wide
                        $string14 = /objects_rbcd_delegation_full\.txt/ nocase ascii wide
                        $string15 = /objects_unconstrained_delegation_full\.txt/ nocase ascii wide
                        $string16 = /smbenum\.run/ nocase ascii wide
                        $string17 = /users_asreproast\.txt/ nocase ascii wide
                        $string18 = /users_dcsrp_full\.txt/ nocase ascii wide
                        $string19 = /users_kerberoasting\.txt/ nocase ascii wide
                        $string20 = /users_no_req_pass\.txt/ nocase ascii wide
                        $string21 = /users_no_req_pass_full\.txt/ nocase ascii wide

    condition:
        any of them
}