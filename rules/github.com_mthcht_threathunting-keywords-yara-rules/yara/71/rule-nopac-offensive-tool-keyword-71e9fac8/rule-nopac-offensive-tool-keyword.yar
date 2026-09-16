rule rule_noPac_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'noPac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noPac"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_noPac_offensive_tool_keyword = "/Ridter/noPac" nocase ascii wide
                        $string2_noPac_offensive_tool_keyword = /AdFind\.exe\s\-sc\sgetacls\s\-sddlfilter\s\s\s.{0,1000}computer.{0,1000}\s\-recmute/ nocase ascii wide
                        $string3_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-create\-child/ nocase ascii wide
                        $string4_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-dc\-host\s/ nocase ascii wide
                        $string5_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-dc\-ip\s/ nocase ascii wide
                        $string6_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-domain\-netbios/ nocase ascii wide
                        $string7_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-dump/ nocase ascii wide
                        $string8_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-hashes\s/ nocase ascii wide
                        $string9_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-\-impersonate\s/ nocase ascii wide
                        $string10_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-just\-dc\-ntlm/ nocase ascii wide
                        $string11_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-just\-dc\-user\s/ nocase ascii wide
                        $string12_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-new\-name\s/ nocase ascii wide
                        $string13_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-no\-add\s/ nocase ascii wide
                        $string14_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-pwd\-last\-set/ nocase ascii wide
                        $string15_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-service\-name\s/ nocase ascii wide
                        $string16_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-shell/ nocase ascii wide
                        $string17_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-shell\-type\s/ nocase ascii wide
                        $string18_noPac_offensive_tool_keyword = /noPac\..{0,1000}\s\-use\-ldap/ nocase ascii wide
                        $string19_noPac_offensive_tool_keyword = /noPac\.py/ nocase ascii wide
                        $string20_noPac_offensive_tool_keyword = /python\snoPac\./ nocase ascii wide
                        $string21_noPac_offensive_tool_keyword = "Ridter/noPac" nocase ascii wide
                        $string22_noPac_offensive_tool_keyword = /S4U2self\.py/ nocase ascii wide
                        $string23_noPac_offensive_tool_keyword = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}