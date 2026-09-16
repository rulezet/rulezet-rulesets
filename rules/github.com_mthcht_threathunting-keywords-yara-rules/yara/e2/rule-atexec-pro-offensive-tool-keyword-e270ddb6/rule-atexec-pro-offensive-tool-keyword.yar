rule rule_atexec_pro_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'atexec-pro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_atexec_pro_offensive_tool_keyword = /\satexec\-pro\.py/ nocase ascii wide
                        $string2_atexec_pro_offensive_tool_keyword = /\/atexec\-pro\.git/ nocase ascii wide
                        $string3_atexec_pro_offensive_tool_keyword = /\/atexec\-pro\.py/ nocase ascii wide
                        $string4_atexec_pro_offensive_tool_keyword = /\/libs\/powershells\/upload\.ps1/
                        $string5_atexec_pro_offensive_tool_keyword = /\/Rubeus\.exe/
                        $string6_atexec_pro_offensive_tool_keyword = /\\atexec\-pro\.py/ nocase ascii wide
                        $string7_atexec_pro_offensive_tool_keyword = /\\atexec\-pro\-main/ nocase ascii wide
                        $string8_atexec_pro_offensive_tool_keyword = "10dbc6cb2d71505d7add5a2927228077142851657f2578b9c774656505338d32" nocase ascii wide
                        $string9_atexec_pro_offensive_tool_keyword = /ATShell\s\(\%s\@\%s\)\>\s/ nocase ascii wide
                        $string10_atexec_pro_offensive_tool_keyword = "dc5a1f72ecaa1cddb1df73ddd075819eb5d2d35f95ea11639cfa1e189ed15217" nocase ascii wide
                        $string11_atexec_pro_offensive_tool_keyword = /impacket\.dcerpc/ nocase ascii wide
                        $string12_atexec_pro_offensive_tool_keyword = /impacket\.krb5/ nocase ascii wide
                        $string13_atexec_pro_offensive_tool_keyword = "Ridter/atexec-pro" nocase ascii wide

    condition:
        any of them
}