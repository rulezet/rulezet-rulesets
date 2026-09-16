rule PowerUpSQL
{
    meta:
        description = "Detection patterns for the tool 'PowerUpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerUpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " evil_DDL_trigger" nocase ascii wide
                        $string2 = /\sFROM\sdbo\.C2Agents/ nocase ascii wide
                        $string3 = " -Name Publisher -Value \"Bad Person\"" nocase ascii wide
                        $string4 = " -Name SQLC2AgentPS " nocase ascii wide
                        $string5 = /\sPowerUpSQL\.ps1/ nocase ascii wide
                        $string6 = /\sSQLC2\.ps1/ nocase ascii wide
                        $string7 = " -TaskName \"SQLC2AgentPS" nocase ascii wide
                        $string8 = /\sUPDATE\sdbo\.C2Agents/ nocase ascii wide
                        $string9 = " WHERE TABLE_NAME like 'C2AGENTS'" nocase ascii wide
                        $string10 = " WHERE TABLE_NAME like 'C2COMMANDS'" nocase ascii wide
                        $string11 = /\$SQLC2Command/ nocase ascii wide
                        $string12 = /\/PowerUpSQL\.ps1/ nocase ascii wide
                        $string13 = /\/SQLC2\.ps1/ nocase ascii wide
                        $string14 = /\:\\windows\\temp\\blah\.txt/ nocase ascii wide
                        $string15 = /\[SQLC2\sAgent\sJob\]/ nocase ascii wide
                        $string16 = /\\Backdoor\.exe/ nocase ascii wide
                        $string17 = /\\evil32\.dll/ nocase ascii wide
                        $string18 = /\\evil64\.dll/ nocase ascii wide
                        $string19 = /\\Get\-Credential\.sql/ nocase ascii wide
                        $string20 = /\\PowerUpSQL\.ps1/ nocase ascii wide
                        $string21 = /\\SQLC2\.ps1/ nocase ascii wide
                        $string22 = /\\SQLC2CMDS\.dll/ nocase ascii wide
                        $string23 = /\\Windows\\CurrentVersion\\Uninstall\\SQLC2AgentPS/ nocase ascii wide
                        $string24 = /\\xp_evil_template\.cpp/ nocase ascii wide
                        $string25 = "<H1>PowerUp report for " nocase ascii wide
                        $string26 = "261a0287a47dd71f44a4494a5d563bd5aa673687f60744ecf559ecb817a7ac82" nocase ascii wide
                        $string27 = /C\:\\temp\\iamahacker\.txt/ nocase ascii wide
                        $string28 = /c\:\\windows\\temp\\blah\.txt/ nocase ascii wide
                        $string29 = "Create-SQLFileCLRDll" nocase ascii wide
                        $string30 = "Create-SQLFileXpDll" nocase ascii wide
                        $string31 = "d090bea299c6fb0956ce4a6450d0bfe1e3e0aa952a67b718f26e3668e41aac56" nocase ascii wide
                        $string32 = /EXECUTE\(\'sp_configure\s\'\'xp_cmdshell\'\'\,1\;reconfigure\;\'/ nocase ascii wide
                        $string33 = "fcbcac521d37905835cbe924d2bca822513682a9cfa0d48945673e5b72d86709" nocase ascii wide
                        $string34 = "Get-DomainSpn" nocase ascii wide
                        $string35 = "Get-MSSQLAllCredentials" nocase ascii wide
                        $string36 = "Get-MSSQLAllCredentials" nocase ascii wide
                        $string37 = "Get-MSSQLCredentialPasswords" nocase ascii wide
                        $string38 = "Get-MSSQLCredentialPasswords" nocase ascii wide
                        $string39 = "Get-MSSQLLinkPasswords" nocase ascii wide
                        $string40 = "Get-SQLC2Agent" nocase ascii wide
                        $string41 = "Get-SQLC2Command " nocase ascii wide
                        $string42 = "Get-SQLC2ComputerNameFromInstance" nocase ascii wide
                        $string43 = "Get-SQLC2Connection" nocase ascii wide
                        $string44 = "Get-SQLC2Query" nocase ascii wide
                        $string45 = "Get-SQLC2Result" nocase ascii wide
                        $string46 = "Get-SQLDomainPasswordsLAPS" nocase ascii wide
                        $string47 = "Get-SQLFuzzDatabaseName" nocase ascii wide
                        $string48 = "Get-SQLFuzzDomainAccount" nocase ascii wide
                        $string49 = "Get-SQLFuzzObjectName" nocase ascii wide
                        $string50 = "Get-SQLFuzzServerLogin'" nocase ascii wide
                        $string51 = "Get-SQLLocalAdminCheck" nocase ascii wide
                        $string52 = "Get-SQLOleDbProvder" nocase ascii wide
                        $string53 = "Get-SQLPersistRegDebugger" nocase ascii wide
                        $string54 = "Get-SQLPersistRegRun" nocase ascii wide
                        $string55 = "Get-SQLPersistTriggerDDL" nocase ascii wide
                        $string56 = "Get-SQLRecoverPwAutoLogon" nocase ascii wide
                        $string57 = "Get-SQLServerCredential" nocase ascii wide
                        $string58 = "Get-SQLServerLinkCrawl" nocase ascii wide
                        $string59 = "Get-SQLServerLoginDefaultPw" nocase ascii wide
                        $string60 = "Get-SQLServerPasswordHash" nocase ascii wide
                        $string61 = "Get-SQLServerPriv" nocase ascii wide
                        $string62 = "Get-SQLServiceAccount" nocase ascii wide
                        $string63 = "Get-SQLServiceAccountPwHashes" nocase ascii wide
                        $string64 = "Get-SQLSysadminCheck" nocase ascii wide
                        $string65 = "Get-SQLTriggerDdl" nocase ascii wide
                        $string66 = "Get-SQLTriggerDml" nocase ascii wide
                        $string67 = "Install-SQLC2AgentLink" nocase ascii wide
                        $string68 = "Install-SQLC2Server" nocase ascii wide
                        $string69 = /Inveigh\-BruteForce\.ps1/ nocase ascii wide
                        $string70 = "Invoke-SQLAuditDefaultLoginPw" nocase ascii wide
                        $string71 = "Invoke-SQLAuditPrivAutoExecSp" nocase ascii wide
                        $string72 = "Invoke-SQLAuditPrivCreateProcedure" nocase ascii wide
                        $string73 = "Invoke-SQLAuditPrivDbChaining" nocase ascii wide
                        $string74 = "Invoke-SQLAuditPrivImpersonateLogin" nocase ascii wide
                        $string75 = "Invoke-SQLAuditPrivServerLink" nocase ascii wide
                        $string76 = "Invoke-SQLAuditPrivTrustworthy" nocase ascii wide
                        $string77 = "Invoke-SQLAuditPrivXpDirtree" nocase ascii wide
                        $string78 = "Invoke-SQLAuditPrivXpFileexit" nocase ascii wide
                        $string79 = "Invoke-SQLAuditSQLiSpExecuteAs" nocase ascii wide
                        $string80 = "Invoke-SQLAuditSQLiSpSigned" nocase ascii wide
                        $string81 = "Invoke-SQLAuditWeakLoginPw" nocase ascii wide
                        $string82 = "Invoke-SQLC2Command" nocase ascii wide
                        $string83 = "Invoke-SQLDumpInfo" nocase ascii wide
                        $string84 = "Invoke-SQLEscalatePriv" nocase ascii wide
                        $string85 = "Invoke-SQLImpersonateService" nocase ascii wide
                        $string86 = "Invoke-SQLImpersonateServiceCmd" nocase ascii wide
                        $string87 = "Invoke-SQLOSCmd" nocase ascii wide
                        $string88 = "Invoke-SQLOSCmdAgentJob" nocase ascii wide
                        $string89 = "Invoke-SQLOSCmdCLR" nocase ascii wide
                        $string90 = "Invoke-SQLOSCmdCOle" nocase ascii wide
                        $string91 = "Invoke-SQLOSCmdPython" nocase ascii wide
                        $string92 = "Invoke-SQLOSCmdR" nocase ascii wide
                        $string93 = "Invoke-SqlServer-Persist-StartupSp" nocase ascii wide
                        $string94 = "Invoke-SqlServer-Persist-TriggerLogon" nocase ascii wide
                        $string95 = "Invoke-SQLUncPathInjection" nocase ascii wide
                        $string96 = "Invoke-SQLUncPathInjection" nocase ascii wide
                        $string97 = "Invoke-TokenManipulation" nocase ascii wide
                        $string98 = "NetSPI/Powershell-Modules" nocase ascii wide
                        $string99 = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\UtilMan\.exe\\"\s\-Name\s/ nocase ascii wide
                        $string100 = "PowerUpSQL" nocase ascii wide
                        $string101 = "Register-SQLC2Agent" nocase ascii wide
                        $string102 = "Remove-SQLC2Agent" nocase ascii wide
                        $string103 = "Remove-SQLC2Command" nocase ascii wide
                        $string104 = /SQLC2CMDS\.dll/ nocase ascii wide
                        $string105 = "Uninstall-SQLC2AgentPs" nocase ascii wide
                        $string106 = "Uninstall-SQLC2Server" nocase ascii wide
                        $string107 = /writefile_bcpxpcmdshell\.sql/ nocase ascii wide
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