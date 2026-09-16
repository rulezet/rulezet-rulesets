rule rule__0d1n_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '0d1n' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0d1n"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__0d1n_offensive_tool_keyword = /\/0d1n\.c/ nocase ascii wide
                        $string2__0d1n_offensive_tool_keyword = "/0d1n_view" nocase ascii wide
                        $string3__0d1n_offensive_tool_keyword = "/bin/0d1n"
                        $string4__0d1n_offensive_tool_keyword = /\/crlfinjection\.txt/ nocase ascii wide
                        $string5__0d1n_offensive_tool_keyword = /\/dir_brute\.txt/ nocase ascii wide
                        $string6__0d1n_offensive_tool_keyword = /\/js_inject\.txt/ nocase ascii wide
                        $string7__0d1n_offensive_tool_keyword = /\/ldap_injection\.txt/ nocase ascii wide
                        $string8__0d1n_offensive_tool_keyword = /\/passive_sqli\.txt/ nocase ascii wide
                        $string9__0d1n_offensive_tool_keyword = /\/password_brute\.txt/ nocase ascii wide
                        $string10__0d1n_offensive_tool_keyword = /\/path_traversal\.txt/ nocase ascii wide
                        $string11__0d1n_offensive_tool_keyword = /\/path_traversal_win32\.txt/ nocase ascii wide
                        $string12__0d1n_offensive_tool_keyword = /\/sqli\.txt/ nocase ascii wide
                        $string13__0d1n_offensive_tool_keyword = /\/xml_attack\.txt/ nocase ascii wide
                        $string14__0d1n_offensive_tool_keyword = /\/xml_attacks\.txt/ nocase ascii wide
                        $string15__0d1n_offensive_tool_keyword = /\/xpath_injection\.txt/ nocase ascii wide
                        $string16__0d1n_offensive_tool_keyword = /\/xss_robertux\.txt/ nocase ascii wide
                        $string17__0d1n_offensive_tool_keyword = /\/xxe_fuzz\.txt/ nocase ascii wide
                        $string18__0d1n_offensive_tool_keyword = /0d1n\s.{0,1000}\s\-\-post\s.{0,1000}\s\-\-payloads\s/ nocase ascii wide
                        $string19__0d1n_offensive_tool_keyword = "0d1n --host" nocase ascii wide
                        $string20__0d1n_offensive_tool_keyword = /0d1n.{0,1000}kill_listener\.sh/ nocase ascii wide
                        $string21__0d1n_offensive_tool_keyword = "CoolerVoid/0d1n" nocase ascii wide

    condition:
        any of them
}