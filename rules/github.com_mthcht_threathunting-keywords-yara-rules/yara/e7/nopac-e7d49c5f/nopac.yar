rule noPac
{
    meta:
        description = "Detection patterns for the tool 'noPac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noPac"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Ridter/noPac" nocase ascii wide
                        $string2 = /AdFind\.exe\s\-sc\sgetacls\s\-sddlfilter\s\s\s.{0,1000}computer.{0,1000}\s\-recmute/ nocase ascii wide
                        $string3 = /noPac\..{0,1000}\s\-create\-child/ nocase ascii wide
                        $string4 = /noPac\..{0,1000}\s\-dc\-host\s/ nocase ascii wide
                        $string5 = /noPac\..{0,1000}\s\-dc\-ip\s/ nocase ascii wide
                        $string6 = /noPac\..{0,1000}\s\-domain\-netbios/ nocase ascii wide
                        $string7 = /noPac\..{0,1000}\s\-dump/ nocase ascii wide
                        $string8 = /noPac\..{0,1000}\s\-hashes\s/ nocase ascii wide
                        $string9 = /noPac\..{0,1000}\s\-\-impersonate\s/ nocase ascii wide
                        $string10 = /noPac\..{0,1000}\s\-just\-dc\-ntlm/ nocase ascii wide
                        $string11 = /noPac\..{0,1000}\s\-just\-dc\-user\s/ nocase ascii wide
                        $string12 = /noPac\..{0,1000}\s\-new\-name\s/ nocase ascii wide
                        $string13 = /noPac\..{0,1000}\s\-no\-add\s/ nocase ascii wide
                        $string14 = /noPac\..{0,1000}\s\-pwd\-last\-set/ nocase ascii wide
                        $string15 = /noPac\..{0,1000}\s\-service\-name\s/ nocase ascii wide
                        $string16 = /noPac\..{0,1000}\s\-shell/ nocase ascii wide
                        $string17 = /noPac\..{0,1000}\s\-shell\-type\s/ nocase ascii wide
                        $string18 = /noPac\..{0,1000}\s\-use\-ldap/ nocase ascii wide
                        $string19 = /noPac\.py/ nocase ascii wide
                        $string20 = /python\snoPac\./ nocase ascii wide
                        $string21 = "Ridter/noPac" nocase ascii wide
                        $string22 = /S4U2self\.py/ nocase ascii wide
                        $string23 = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}