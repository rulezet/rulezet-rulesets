rule PSMapExec
{
    meta:
        description = "Detection patterns for the tool 'PSMapExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " - Removed disabled accounts from spraying" nocase ascii wide
                        $string2 = /\s\$KerbDump/ nocase ascii wide
                        $string3 = " -Method GenRelayList" nocase ascii wide
                        $string4 = " -Method SessionHunter" nocase ascii wide
                        $string5 = " -Method Spray -AccountAsPassword" nocase ascii wide
                        $string6 = " -Method Spray -EmptyPassword" nocase ascii wide
                        $string7 = " -Method Spray -Hash " nocase ascii wide
                        $string8 = " -Method Spray -Password " nocase ascii wide
                        $string9 = " -Module kerbdump" nocase ascii wide
                        $string10 = /\s\-Name\s\\"Test\.PME\\"\s/ nocase ascii wide
                        $string11 = /\s\-notcontains\s.{0,1000}\s\-notlike\s\\"ntuser\.dat.{0,1000}\\"\s\-and\s\$_\.Extension\s\-ne\s\\"\.tm/ nocase ascii wide
                        $string12 = /\s\-Targets\s.{0,1000}\s\-Method\s.{0,1000}\s\-LocalAuth/ nocase ascii wide
                        $string13 = " -Targets All -Method WMI" nocase ascii wide
                        $string14 = " -Targets DCs" nocase ascii wide
                        $string15 = /\swill\sbe\swritten\sto\sPME\\/ nocase ascii wide
                        $string16 = "\"Successful Connection PME\"" nocase ascii wide
                        $string17 = /\$BaseTicket\s\|\sSelect\-String\s\-Pattern\s\'doI\./ nocase ascii wide
                        $string18 = /\$FQDNDomainPlusAccountOperators/ nocase ascii wide
                        $string19 = /\$FQDNDomainPlusDomainAdmins/ nocase ascii wide
                        $string20 = /\$FQDNDomainPlusEnterpriseAdmins/ nocase ascii wide
                        $string21 = /\$FQDNDomainPlusServerOperators/ nocase ascii wide
                        $string22 = /\$MimiTickets/ nocase ascii wide
                        $string23 = /\$newClass\[\\"__CLASS\\"\]\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string24 = /\/Kirby\.ps1/ nocase ascii wide
                        $string25 = /\/PsMapExec\.git/ nocase ascii wide
                        $string26 = "/PsMapExec/" nocase ascii wide
                        $string27 = /\[string\]\$Class\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string28 = /\\\.eKeys\-Parsed\.txt/ nocase ascii wide
                        $string29 = /\\\\\$ComputerName\sdelete\s\$ServiceName/ nocase ascii wide
                        $string30 = /\\\\.{0,1000}\screate\sService_.{0,1000}\sbinpath\=\s\`\\"C\:\\Windows\\System32\\cmd\.exe\s\/c\spowershell\.exe\s\-enc\s/ nocase ascii wide
                        $string31 = /\\Kirby\.ps1/ nocase ascii wide
                        $string32 = /\\Kirby\.ps1/ nocase ascii wide
                        $string33 = /\\PME\\.{0,1000}\-ConsoleHistory\.txt/ nocase ascii wide
                        $string34 = /\\PME\\Console\sHistory\\/ nocase ascii wide
                        $string35 = /\\PME\\eKeys\\/ nocase ascii wide
                        $string36 = /\\PME\\LogonPasswords/ nocase ascii wide
                        $string37 = /\\PME\\LSA\\/ nocase ascii wide
                        $string38 = /\\PME\\MSSQL\\/ nocase ascii wide
                        $string39 = /\\PME\\SAM\\/ nocase ascii wide
                        $string40 = /\\PME\\Sessions\\/ nocase ascii wide
                        $string41 = /\\PME\\SMB\\/ nocase ascii wide
                        $string42 = /\\PME\\Spraying\\/ nocase ascii wide
                        $string43 = /\\PME\\Tickets\\Kerbdump/ nocase ascii wide
                        $string44 = /\\PME\\Tickets\\MimiTickets/ nocase ascii wide
                        $string45 = /\\PME\\User\sFiles\\/ nocase ascii wide
                        $string46 = /\\PME\\VNC\\/ nocase ascii wide
                        $string47 = /\\SAM\\\.Sam\-Full\.txt/ nocase ascii wide
                        $string48 = /\\Sessions\\SH\-MatchedGroups\-.{0,1000}\.txt/ nocase ascii wide
                        $string49 = /\\Test\.PME/ nocase ascii wide
                        $string50 = /\\Tickets\\KerbDump/ nocase ascii wide
                        $string51 = /\\VNC\\\.VNC\-Non\-Auth\.txt/ nocase ascii wide
                        $string52 = /\|IEX\}DumpSAM/ nocase ascii wide
                        $string53 = /asktgt\s\/user.{0,1000}\s\/domain\:.{0,1000}\s\/password\:.{0,1000}\s\/opsec\s\/force\s\/ptt/ nocase ascii wide
                        $string54 = /Assembly\.GetType\(\\"System\.Management\.Automation\.AmsiUtils\\"\)\.getField\(\\"amsiInitFailed\\".{0,1000}\'NonPublic.{0,1000}Static\'\)\.SetValue\(\$null.{0,1000}\$true\)/ nocase ascii wide
                        $string55 = /ComputerDirectory\\.{0,1000}\.FullDump\.txt/ nocase ascii wide
                        $string56 = "Created directory for PME at " nocase ascii wide
                        $string57 = "dump /service:krbtgt " nocase ascii wide
                        $string58 = /DumpSAM\.ps1/ nocase ascii wide
                        $string59 = "earching for systems where privileged users' credentials might be in running memory" nocase ascii wide
                        $string60 = /eKeys\\.{0,1000}\-eKeys\.txt/ nocase ascii wide
                        $string61 = /\-EmptyPassword\-Users\.txt/ nocase ascii wide
                        $string62 = "function DumpSAM" nocase ascii wide
                        $string63 = /function\sGNLPH.{0,1000}Get\-ItemProperty\s\\"HKLM\:SAM\\SAM\\Domains\\Account\\Users\\/ nocase ascii wide
                        $string64 = "Function PsMapExec" nocase ascii wide
                        $string65 = "Get-GroupMembers -GroupName \"Account Operators\"" nocase ascii wide
                        $string66 = "Get-GroupMembers -GroupName \"Domain Admins\"" nocase ascii wide
                        $string67 = "Get-GroupMembers -GroupName \"Enterprise Admins\"" nocase ascii wide
                        $string68 = "Get-GroupMembers -GroupName \"Server Operators\"" nocase ascii wide
                        $string69 = "H4sIAAAAAAAEACVQ30vDMBB" nocase ascii wide
                        $string70 = "H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc" nocase ascii wide
                        $string71 = "H4sIAAAAAAAEAOx9CVhTR9fw3CQkYScgqyAILsgm" nocase ascii wide
                        $string72 = /https\:\/\/github\.com\/The\-Viper\-One/ nocase ascii wide
                        $string73 = /https\:\/\/viperone\.gitbook\.io\/pentest\-everything/ nocase ascii wide
                        $string74 = /IAS\s\-Process\s.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
                        $string75 = /IAS\s\-Process\s\{GNLPH\}.{0,1000}\$excludedUsernames\=\@\(\\"Guest.{0,1000}DefaultAccount.{0,1000}WDAGUtilityAccount/ nocase ascii wide
                        $string76 = /InjectTicket.{0,1000}ptt\s\/ticket\:/ nocase ascii wide
                        $string77 = "Invoke-Mongoose" nocase ascii wide
                        $string78 = "Invoke-MSSQLup" nocase ascii wide
                        $string79 = "Invoke-NETMongoose" nocase ascii wide
                        $string80 = /Invoke\-NTDS\.ps1/ nocase ascii wide
                        $string81 = "Invoke-Pandemonium -Command" nocase ascii wide
                        $string82 = /Invoke\-Pandemonium\.ps1/ nocase ascii wide
                        $string83 = "Invoke-Rubeus " nocase ascii wide
                        $string84 = "Invoke-Rubeus" nocase ascii wide
                        $string85 = /Invoke\-SecretsDump\.ps1/ nocase ascii wide
                        $string86 = "Invoke-SharpRDP" nocase ascii wide
                        $string87 = "Invoke-SharpRDPTest" nocase ascii wide
                        $string88 = /KerbDump\\.{0,1000}\-Tickets\-KerbDump\.txt/ nocase ascii wide
                        $string89 = /LogonPasswords\\.{0,1000}\-LogonPasswords\.txt/ nocase ascii wide
                        $string90 = /LogonPasswords\\\.AllUniqueNTLM\.txt/ nocase ascii wide
                        $string91 = /MimiTickets\\.{0,1000}\-Tickets\.txt/ nocase ascii wide
                        $string92 = /New\-Object\sSystem\.Management\.ManagementClass\(\\"\\\\\\\$env\:computername\\root\\cimv2.{0,1000}\[\\"__CLASS\\"\]\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string93 = /PME\\LSA\\.{0,1000}\-LSA\.txt/ nocase ascii wide
                        $string94 = /PME\\UserFiles\\.{0,1000}\-UserFiles\.txt/ nocase ascii wide
                        $string95 = "PsMapExec -" nocase ascii wide
                        $string96 = "PsMapExec will continue in the current users context" nocase ascii wide
                        $string97 = /PsMapExec\.ps1/ nocase ascii wide
                        $string98 = "PsMapExec-main" nocase ascii wide
                        $string99 = /SAM\\.{0,1000}\-SAMHashes\.txt/ nocase ascii wide
                        $string100 = /SAM\\.{0,1000}\-SAMHashes\.txt/ nocase ascii wide
                        $string101 = /SAM\\\.Sam\-Full\.txt/ nocase ascii wide
                        $string102 = /SMB\\SigningNotRequired\-.{0,1000}\.txt/ nocase ascii wide
                        $string103 = /Specified\suser\sis\sa\sDomain\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
                        $string104 = /Specified\suser\sis\sa\sEnterprise\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
                        $string105 = "Spraying empty passwords" nocase ascii wide
                        $string106 = "Spraying usernames as passwords" nocase ascii wide
                        $string107 = /Spraying\\.{0,1000}\-AccountAsPassword\-Users\.txt/ nocase ascii wide
                        $string108 = /Spraying\\.{0,1000}\-Password\-Users\.txt/ nocase ascii wide
                        $string109 = "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash" nocase ascii wide
                        $string110 = "tgtdeleg /nowrap" nocase ascii wide
                        $string111 = "The-Viper-One/PME-Scripts" nocase ascii wide
                        $string112 = "The-Viper-One/PsMapExec" nocase ascii wide
                        $string113 = /to\s\$LogonPasswords/ nocase ascii wide
                        $string114 = "Unhandled Rubeus exception:" nocase ascii wide
                        $string115 = /VNC\-NoAuth\s\-ComputerName\s.{0,1000}\s\-Port\s/ nocase ascii wide

    condition:
        any of them
}