rule CIMplant
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -c active_users -u " nocase ascii wide
                        $string2 = " -c command_exec --execute tasklist" nocase ascii wide
                        $string3 = " -c command_exec --execute whoami" nocase ascii wide
                        $string4 = " -c edr_query " nocase ascii wide
                        $string5 = /\s\-c\slogon_events\s.{0,1000}\s\-u\s/ nocase ascii wide
                        $string6 = /\s\-c\sls\s\-\-directory\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string7 = " -c process_kill --process " nocase ascii wide
                        $string8 = " -c service_mod --execute create -s " nocase ascii wide
                        $string9 = /\s\-c\supload\s\-\-fileto\s.{0,1000}\s\-\-file\s/ nocase ascii wide
                        $string10 = /\s\-c\svacant_system\s.{0,1000}\s\-u\s/ nocase ascii wide
                        $string11 = /\sCIMplant\.exe/ nocase ascii wide
                        $string12 = /\s\-s\s.{0,1000}\s\-c\scommand_exec\s\-\-execute\s/ nocase ascii wide
                        $string13 = /\s\-s\s.{0,1000}\s\-c\sdisable_wdigest\s/ nocase ascii wide
                        $string14 = /\s\-s\s.{0,1000}\s\-c\sdisable_winrm\s/ nocase ascii wide
                        $string15 = /\s\-s\s.{0,1000}\s\-c\senable_wdigest\s/ nocase ascii wide
                        $string16 = /\s\-s\s.{0,1000}\s\-c\senable_winrm\s/ nocase ascii wide
                        $string17 = /\s\-s\s.{0,1000}\s\-c\sremote_posh\s/ nocase ascii wide
                        $string18 = " --service fortynorth" nocase ascii wide
                        $string19 = /\.exe\s\-s\s.{0,1000}\s\-c\sservice_mod\s/ nocase ascii wide
                        $string20 = /\/CIMplant\.exe/ nocase ascii wide
                        $string21 = /\/CIMplant\.git/ nocase ascii wide
                        $string22 = /\/CIMplant\/Commander\.cs/ nocase ascii wide
                        $string23 = /\\CIMplant\.exe/ nocase ascii wide
                        $string24 = /CIMplant\.exe\s/ nocase ascii wide
                        $string25 = /CIMplant\.sln/ nocase ascii wide
                        $string26 = "CIMplant-main" nocase ascii wide
                        $string27 = "FortyNorthSecurity/CIMplant" nocase ascii wide
                        $string28 = "RedSiege/CIMplant" nocase ascii wide

    condition:
        any of them
}