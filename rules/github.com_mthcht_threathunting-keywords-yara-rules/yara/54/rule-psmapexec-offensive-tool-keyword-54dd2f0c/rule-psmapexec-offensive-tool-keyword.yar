rule rule_PSMapExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSMapExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSMapExec_offensive_tool_keyword = " - Removed disabled accounts from spraying" nocase ascii wide
                        $string2_PSMapExec_offensive_tool_keyword = /\s\$KerbDump/ nocase ascii wide
                        $string3_PSMapExec_offensive_tool_keyword = " -Method GenRelayList" nocase ascii wide
                        $string4_PSMapExec_offensive_tool_keyword = " -Method SessionHunter" nocase ascii wide
                        $string5_PSMapExec_offensive_tool_keyword = " -Method Spray -AccountAsPassword" nocase ascii wide
                        $string6_PSMapExec_offensive_tool_keyword = " -Method Spray -EmptyPassword" nocase ascii wide
                        $string7_PSMapExec_offensive_tool_keyword = " -Method Spray -Hash " nocase ascii wide
                        $string8_PSMapExec_offensive_tool_keyword = " -Method Spray -Password " nocase ascii wide
                        $string9_PSMapExec_offensive_tool_keyword = " -Module kerbdump" nocase ascii wide
                        $string10_PSMapExec_offensive_tool_keyword = /\s\-Name\s\\"Test\.PME\\"\s/ nocase ascii wide
                        $string11_PSMapExec_offensive_tool_keyword = /\s\-notcontains\s.{0,100}\s\-notlike\s\\"ntuser\.dat.{0,100}\\"\s\-and\s\$_\.Extension\s\-ne\s\\"\.tm/ nocase ascii wide
                        $string12_PSMapExec_offensive_tool_keyword = /\s\-Targets\s.{0,100}\s\-Method\s.{0,100}\s\-LocalAuth/ nocase ascii wide
                        $string13_PSMapExec_offensive_tool_keyword = " -Targets All -Method WMI" nocase ascii wide
                        $string14_PSMapExec_offensive_tool_keyword = " -Targets DCs" nocase ascii wide
                        $string15_PSMapExec_offensive_tool_keyword = /\swill\sbe\swritten\sto\sPME\\/ nocase ascii wide
                        $string16_PSMapExec_offensive_tool_keyword = "\"Successful Connection PME\"" nocase ascii wide
                        $string17_PSMapExec_offensive_tool_keyword = /\$BaseTicket\s\|\sSelect\-String\s\-Pattern\s\'doI\./ nocase ascii wide
                        $string18_PSMapExec_offensive_tool_keyword = /\$FQDNDomainPlusAccountOperators/ nocase ascii wide
                        $string19_PSMapExec_offensive_tool_keyword = /\$FQDNDomainPlusDomainAdmins/ nocase ascii wide
                        $string20_PSMapExec_offensive_tool_keyword = /\$FQDNDomainPlusEnterpriseAdmins/ nocase ascii wide
                        $string21_PSMapExec_offensive_tool_keyword = /\$FQDNDomainPlusServerOperators/ nocase ascii wide
                        $string22_PSMapExec_offensive_tool_keyword = /\$MimiTickets/ nocase ascii wide
                        $string23_PSMapExec_offensive_tool_keyword = /\$newClass\[\\"__CLASS\\"\]\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string24_PSMapExec_offensive_tool_keyword = /\/Kirby\.ps1/ nocase ascii wide
                        $string25_PSMapExec_offensive_tool_keyword = /\/PsMapExec\.git/ nocase ascii wide
                        $string26_PSMapExec_offensive_tool_keyword = "/PsMapExec/" nocase ascii wide
                        $string27_PSMapExec_offensive_tool_keyword = /\[string\]\$Class\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string28_PSMapExec_offensive_tool_keyword = /\\\.eKeys\-Parsed\.txt/ nocase ascii wide
                        $string29_PSMapExec_offensive_tool_keyword = /\\\\\$ComputerName\sdelete\s\$ServiceName/ nocase ascii wide
                        $string30_PSMapExec_offensive_tool_keyword = /\\\\.{0,100}\screate\sService_.{0,100}\sbinpath\=\s\`\\"C\:\\Windows\\System32\\cmd\.exe\s\/c\spowershell\.exe\s\-enc\s/ nocase ascii wide
                        $string31_PSMapExec_offensive_tool_keyword = /\\Kirby\.ps1/ nocase ascii wide
                        $string32_PSMapExec_offensive_tool_keyword = /\\Kirby\.ps1/ nocase ascii wide
                        $string33_PSMapExec_offensive_tool_keyword = /\\PME\\.{0,100}\-ConsoleHistory\.txt/ nocase ascii wide
                        $string34_PSMapExec_offensive_tool_keyword = /\\PME\\Console\sHistory\\/ nocase ascii wide
                        $string35_PSMapExec_offensive_tool_keyword = /\\PME\\eKeys\\/ nocase ascii wide
                        $string36_PSMapExec_offensive_tool_keyword = /\\PME\\LogonPasswords/ nocase ascii wide
                        $string37_PSMapExec_offensive_tool_keyword = /\\PME\\LSA\\/ nocase ascii wide
                        $string38_PSMapExec_offensive_tool_keyword = /\\PME\\MSSQL\\/ nocase ascii wide
                        $string39_PSMapExec_offensive_tool_keyword = /\\PME\\SAM\\/ nocase ascii wide
                        $string40_PSMapExec_offensive_tool_keyword = /\\PME\\Sessions\\/ nocase ascii wide
                        $string41_PSMapExec_offensive_tool_keyword = /\\PME\\SMB\\/ nocase ascii wide
                        $string42_PSMapExec_offensive_tool_keyword = /\\PME\\Spraying\\/ nocase ascii wide
                        $string43_PSMapExec_offensive_tool_keyword = /\\PME\\Tickets\\Kerbdump/ nocase ascii wide
                        $string44_PSMapExec_offensive_tool_keyword = /\\PME\\Tickets\\MimiTickets/ nocase ascii wide
                        $string45_PSMapExec_offensive_tool_keyword = /\\PME\\User\sFiles\\/ nocase ascii wide
                        $string46_PSMapExec_offensive_tool_keyword = /\\PME\\VNC\\/ nocase ascii wide
                        $string47_PSMapExec_offensive_tool_keyword = /\\SAM\\\.Sam\-Full\.txt/ nocase ascii wide
                        $string48_PSMapExec_offensive_tool_keyword = /\\Sessions\\SH\-MatchedGroups\-.{0,100}\.txt/ nocase ascii wide
                        $string49_PSMapExec_offensive_tool_keyword = /\\Test\.PME/ nocase ascii wide
                        $string50_PSMapExec_offensive_tool_keyword = /\\Tickets\\KerbDump/ nocase ascii wide
                        $string51_PSMapExec_offensive_tool_keyword = /\\VNC\\\.VNC\-Non\-Auth\.txt/ nocase ascii wide
                        $string52_PSMapExec_offensive_tool_keyword = /\|IEX\}DumpSAM/ nocase ascii wide
                        $string53_PSMapExec_offensive_tool_keyword = /asktgt\s\/user.{0,100}\s\/domain\:.{0,100}\s\/password\:.{0,100}\s\/opsec\s\/force\s\/ptt/ nocase ascii wide
                        $string54_PSMapExec_offensive_tool_keyword = /Assembly\.GetType\(\\"System\.Management\.Automation\.AmsiUtils\\"\)\.getField\(\\"amsiInitFailed\\".{0,100}\'NonPublic.{0,100}Static\'\)\.SetValue\(\$null.{0,100}\$true\)/ nocase ascii wide
                        $string55_PSMapExec_offensive_tool_keyword = /ComputerDirectory\\.{0,100}\.FullDump\.txt/ nocase ascii wide
                        $string56_PSMapExec_offensive_tool_keyword = "Created directory for PME at " nocase ascii wide
                        $string57_PSMapExec_offensive_tool_keyword = "dump /service:krbtgt " nocase ascii wide
                        $string58_PSMapExec_offensive_tool_keyword = /DumpSAM\.ps1/ nocase ascii wide
                        $string59_PSMapExec_offensive_tool_keyword = "earching for systems where privileged users' credentials might be in running memory" nocase ascii wide
                        $string60_PSMapExec_offensive_tool_keyword = /eKeys\\.{0,100}\-eKeys\.txt/ nocase ascii wide
                        $string61_PSMapExec_offensive_tool_keyword = /\-EmptyPassword\-Users\.txt/ nocase ascii wide
                        $string62_PSMapExec_offensive_tool_keyword = "function DumpSAM" nocase ascii wide
                        $string63_PSMapExec_offensive_tool_keyword = /function\sGNLPH.{0,100}Get\-ItemProperty\s\\"HKLM\:SAM\\SAM\\Domains\\Account\\Users\\/ nocase ascii wide
                        $string64_PSMapExec_offensive_tool_keyword = "Function PsMapExec" nocase ascii wide
                        $string65_PSMapExec_offensive_tool_keyword = "Get-GroupMembers -GroupName \"Account Operators\"" nocase ascii wide
                        $string66_PSMapExec_offensive_tool_keyword = "Get-GroupMembers -GroupName \"Domain Admins\"" nocase ascii wide
                        $string67_PSMapExec_offensive_tool_keyword = "Get-GroupMembers -GroupName \"Enterprise Admins\"" nocase ascii wide
                        $string68_PSMapExec_offensive_tool_keyword = "Get-GroupMembers -GroupName \"Server Operators\"" nocase ascii wide
                        $string69_PSMapExec_offensive_tool_keyword = "H4sIAAAAAAAEACVQ30vDMBB" nocase ascii wide
                        $string70_PSMapExec_offensive_tool_keyword = "H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc" nocase ascii wide
                        $string71_PSMapExec_offensive_tool_keyword = "H4sIAAAAAAAEAOx9CVhTR9fw3CQkYScgqyAILsgm" nocase ascii wide
                        $string72_PSMapExec_offensive_tool_keyword = /https\:\/\/github\.com\/The\-Viper\-One/ nocase ascii wide
                        $string73_PSMapExec_offensive_tool_keyword = /https\:\/\/viperone\.gitbook\.io\/pentest\-everything/ nocase ascii wide
                        $string74_PSMapExec_offensive_tool_keyword = /IAS\s\-Process\s.{0,100}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
                        $string75_PSMapExec_offensive_tool_keyword = /IAS\s\-Process\s\{GNLPH\}.{0,100}\$excludedUsernames\=\@\(\\"Guest.{0,100}DefaultAccount.{0,100}WDAGUtilityAccount/ nocase ascii wide
                        $string76_PSMapExec_offensive_tool_keyword = /InjectTicket.{0,100}ptt\s\/ticket\:/ nocase ascii wide
                        $string77_PSMapExec_offensive_tool_keyword = "Invoke-Mongoose" nocase ascii wide
                        $string78_PSMapExec_offensive_tool_keyword = "Invoke-MSSQLup" nocase ascii wide
                        $string79_PSMapExec_offensive_tool_keyword = "Invoke-NETMongoose" nocase ascii wide
                        $string80_PSMapExec_offensive_tool_keyword = /Invoke\-NTDS\.ps1/ nocase ascii wide
                        $string81_PSMapExec_offensive_tool_keyword = "Invoke-Pandemonium -Command" nocase ascii wide
                        $string82_PSMapExec_offensive_tool_keyword = /Invoke\-Pandemonium\.ps1/ nocase ascii wide
                        $string83_PSMapExec_offensive_tool_keyword = "Invoke-Rubeus " nocase ascii wide
                        $string84_PSMapExec_offensive_tool_keyword = "Invoke-Rubeus" nocase ascii wide
                        $string85_PSMapExec_offensive_tool_keyword = /Invoke\-SecretsDump\.ps1/ nocase ascii wide
                        $string86_PSMapExec_offensive_tool_keyword = "Invoke-SharpRDP" nocase ascii wide
                        $string87_PSMapExec_offensive_tool_keyword = "Invoke-SharpRDPTest" nocase ascii wide
                        $string88_PSMapExec_offensive_tool_keyword = /KerbDump\\.{0,100}\-Tickets\-KerbDump\.txt/ nocase ascii wide
                        $string89_PSMapExec_offensive_tool_keyword = /LogonPasswords\\.{0,100}\-LogonPasswords\.txt/ nocase ascii wide
                        $string90_PSMapExec_offensive_tool_keyword = /LogonPasswords\\\.AllUniqueNTLM\.txt/ nocase ascii wide
                        $string91_PSMapExec_offensive_tool_keyword = /MimiTickets\\.{0,100}\-Tickets\.txt/ nocase ascii wide
                        $string92_PSMapExec_offensive_tool_keyword = /New\-Object\sSystem\.Management\.ManagementClass\(\\"\\\\\\\$env\:computername\\root\\cimv2.{0,100}\[\\"__CLASS\\"\]\s\=\s\\"PMEClass\\"/ nocase ascii wide
                        $string93_PSMapExec_offensive_tool_keyword = /PME\\LSA\\.{0,100}\-LSA\.txt/ nocase ascii wide
                        $string94_PSMapExec_offensive_tool_keyword = /PME\\UserFiles\\.{0,100}\-UserFiles\.txt/ nocase ascii wide
                        $string95_PSMapExec_offensive_tool_keyword = "PsMapExec -" nocase ascii wide
                        $string96_PSMapExec_offensive_tool_keyword = "PsMapExec will continue in the current users context" nocase ascii wide
                        $string97_PSMapExec_offensive_tool_keyword = /PsMapExec\.ps1/ nocase ascii wide
                        $string98_PSMapExec_offensive_tool_keyword = "PsMapExec-main" nocase ascii wide
                        $string99_PSMapExec_offensive_tool_keyword = /SAM\\.{0,100}\-SAMHashes\.txt/ nocase ascii wide
                        $string100_PSMapExec_offensive_tool_keyword = /SAM\\.{0,100}\-SAMHashes\.txt/ nocase ascii wide
                        $string101_PSMapExec_offensive_tool_keyword = /SAM\\\.Sam\-Full\.txt/ nocase ascii wide
                        $string102_PSMapExec_offensive_tool_keyword = /SMB\\SigningNotRequired\-.{0,100}\.txt/ nocase ascii wide
                        $string103_PSMapExec_offensive_tool_keyword = /Specified\suser\sis\sa\sDomain\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
                        $string104_PSMapExec_offensive_tool_keyword = /Specified\suser\sis\sa\sEnterprise\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
                        $string105_PSMapExec_offensive_tool_keyword = "Spraying empty passwords" nocase ascii wide
                        $string106_PSMapExec_offensive_tool_keyword = "Spraying usernames as passwords" nocase ascii wide
                        $string107_PSMapExec_offensive_tool_keyword = /Spraying\\.{0,100}\-AccountAsPassword\-Users\.txt/ nocase ascii wide
                        $string108_PSMapExec_offensive_tool_keyword = /Spraying\\.{0,100}\-Password\-Users\.txt/ nocase ascii wide
                        $string109_PSMapExec_offensive_tool_keyword = "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash" nocase ascii wide
                        $string110_PSMapExec_offensive_tool_keyword = "tgtdeleg /nowrap" nocase ascii wide
                        $string111_PSMapExec_offensive_tool_keyword = "The-Viper-One/PME-Scripts" nocase ascii wide
                        $string112_PSMapExec_offensive_tool_keyword = "The-Viper-One/PsMapExec" nocase ascii wide
                        $string113_PSMapExec_offensive_tool_keyword = /to\s\$LogonPasswords/ nocase ascii wide
                        $string114_PSMapExec_offensive_tool_keyword = "Unhandled Rubeus exception:" nocase ascii wide
                        $string115_PSMapExec_offensive_tool_keyword = /VNC\-NoAuth\s\-ComputerName\s.{0,100}\s\-Port\s/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}