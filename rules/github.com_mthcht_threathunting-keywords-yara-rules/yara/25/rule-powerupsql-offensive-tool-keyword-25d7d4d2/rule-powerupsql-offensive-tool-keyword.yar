rule rule_PowerUpSQL_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerUpSQL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerUpSQL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerUpSQL_offensive_tool_keyword = " evil_DDL_trigger" nocase ascii wide
                        $string2_PowerUpSQL_offensive_tool_keyword = /\sFROM\sdbo\.C2Agents/ nocase ascii wide
                        $string3_PowerUpSQL_offensive_tool_keyword = " -Name Publisher -Value \"Bad Person\"" nocase ascii wide
                        $string4_PowerUpSQL_offensive_tool_keyword = " -Name SQLC2AgentPS " nocase ascii wide
                        $string5_PowerUpSQL_offensive_tool_keyword = /\sPowerUpSQL\.ps1/ nocase ascii wide
                        $string6_PowerUpSQL_offensive_tool_keyword = /\sSQLC2\.ps1/ nocase ascii wide
                        $string7_PowerUpSQL_offensive_tool_keyword = " -TaskName \"SQLC2AgentPS" nocase ascii wide
                        $string8_PowerUpSQL_offensive_tool_keyword = /\sUPDATE\sdbo\.C2Agents/ nocase ascii wide
                        $string9_PowerUpSQL_offensive_tool_keyword = " WHERE TABLE_NAME like 'C2AGENTS'" nocase ascii wide
                        $string10_PowerUpSQL_offensive_tool_keyword = " WHERE TABLE_NAME like 'C2COMMANDS'" nocase ascii wide
                        $string11_PowerUpSQL_offensive_tool_keyword = /\$SQLC2Command/ nocase ascii wide
                        $string12_PowerUpSQL_offensive_tool_keyword = /\/PowerUpSQL\.ps1/ nocase ascii wide
                        $string13_PowerUpSQL_offensive_tool_keyword = /\/SQLC2\.ps1/ nocase ascii wide
                        $string14_PowerUpSQL_offensive_tool_keyword = /\:\\windows\\temp\\blah\.txt/ nocase ascii wide
                        $string15_PowerUpSQL_offensive_tool_keyword = /\[SQLC2\sAgent\sJob\]/ nocase ascii wide
                        $string16_PowerUpSQL_offensive_tool_keyword = /\\Backdoor\.exe/ nocase ascii wide
                        $string17_PowerUpSQL_offensive_tool_keyword = /\\evil32\.dll/ nocase ascii wide
                        $string18_PowerUpSQL_offensive_tool_keyword = /\\evil64\.dll/ nocase ascii wide
                        $string19_PowerUpSQL_offensive_tool_keyword = /\\Get\-Credential\.sql/ nocase ascii wide
                        $string20_PowerUpSQL_offensive_tool_keyword = /\\PowerUpSQL\.ps1/ nocase ascii wide
                        $string21_PowerUpSQL_offensive_tool_keyword = /\\SQLC2\.ps1/ nocase ascii wide
                        $string22_PowerUpSQL_offensive_tool_keyword = /\\SQLC2CMDS\.dll/ nocase ascii wide
                        $string23_PowerUpSQL_offensive_tool_keyword = /\\Windows\\CurrentVersion\\Uninstall\\SQLC2AgentPS/ nocase ascii wide
                        $string24_PowerUpSQL_offensive_tool_keyword = /\\xp_evil_template\.cpp/ nocase ascii wide
                        $string25_PowerUpSQL_offensive_tool_keyword = "<H1>PowerUp report for " nocase ascii wide
                        $string26_PowerUpSQL_offensive_tool_keyword = "261a0287a47dd71f44a4494a5d563bd5aa673687f60744ecf559ecb817a7ac82" nocase ascii wide
                        $string27_PowerUpSQL_offensive_tool_keyword = /C\:\\temp\\iamahacker\.txt/ nocase ascii wide
                        $string28_PowerUpSQL_offensive_tool_keyword = /c\:\\windows\\temp\\blah\.txt/ nocase ascii wide
                        $string29_PowerUpSQL_offensive_tool_keyword = "Create-SQLFileCLRDll" nocase ascii wide
                        $string30_PowerUpSQL_offensive_tool_keyword = "Create-SQLFileXpDll" nocase ascii wide
                        $string31_PowerUpSQL_offensive_tool_keyword = "d090bea299c6fb0956ce4a6450d0bfe1e3e0aa952a67b718f26e3668e41aac56" nocase ascii wide
                        $string32_PowerUpSQL_offensive_tool_keyword = /EXECUTE\(\'sp_configure\s\'\'xp_cmdshell\'\'\,1\;reconfigure\;\'/ nocase ascii wide
                        $string33_PowerUpSQL_offensive_tool_keyword = "fcbcac521d37905835cbe924d2bca822513682a9cfa0d48945673e5b72d86709" nocase ascii wide
                        $string34_PowerUpSQL_offensive_tool_keyword = "Get-DomainSpn" nocase ascii wide
                        $string35_PowerUpSQL_offensive_tool_keyword = "Get-MSSQLAllCredentials" nocase ascii wide
                        $string36_PowerUpSQL_offensive_tool_keyword = "Get-MSSQLAllCredentials" nocase ascii wide
                        $string37_PowerUpSQL_offensive_tool_keyword = "Get-MSSQLCredentialPasswords" nocase ascii wide
                        $string38_PowerUpSQL_offensive_tool_keyword = "Get-MSSQLCredentialPasswords" nocase ascii wide
                        $string39_PowerUpSQL_offensive_tool_keyword = "Get-MSSQLLinkPasswords" nocase ascii wide
                        $string40_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2Agent" nocase ascii wide
                        $string41_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2Command " nocase ascii wide
                        $string42_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2ComputerNameFromInstance" nocase ascii wide
                        $string43_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2Connection" nocase ascii wide
                        $string44_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2Query" nocase ascii wide
                        $string45_PowerUpSQL_offensive_tool_keyword = "Get-SQLC2Result" nocase ascii wide
                        $string46_PowerUpSQL_offensive_tool_keyword = "Get-SQLDomainPasswordsLAPS" nocase ascii wide
                        $string47_PowerUpSQL_offensive_tool_keyword = "Get-SQLFuzzDatabaseName" nocase ascii wide
                        $string48_PowerUpSQL_offensive_tool_keyword = "Get-SQLFuzzDomainAccount" nocase ascii wide
                        $string49_PowerUpSQL_offensive_tool_keyword = "Get-SQLFuzzObjectName" nocase ascii wide
                        $string50_PowerUpSQL_offensive_tool_keyword = "Get-SQLFuzzServerLogin'" nocase ascii wide
                        $string51_PowerUpSQL_offensive_tool_keyword = "Get-SQLLocalAdminCheck" nocase ascii wide
                        $string52_PowerUpSQL_offensive_tool_keyword = "Get-SQLOleDbProvder" nocase ascii wide
                        $string53_PowerUpSQL_offensive_tool_keyword = "Get-SQLPersistRegDebugger" nocase ascii wide
                        $string54_PowerUpSQL_offensive_tool_keyword = "Get-SQLPersistRegRun" nocase ascii wide
                        $string55_PowerUpSQL_offensive_tool_keyword = "Get-SQLPersistTriggerDDL" nocase ascii wide
                        $string56_PowerUpSQL_offensive_tool_keyword = "Get-SQLRecoverPwAutoLogon" nocase ascii wide
                        $string57_PowerUpSQL_offensive_tool_keyword = "Get-SQLServerCredential" nocase ascii wide
                        $string58_PowerUpSQL_offensive_tool_keyword = "Get-SQLServerLinkCrawl" nocase ascii wide
                        $string59_PowerUpSQL_offensive_tool_keyword = "Get-SQLServerLoginDefaultPw" nocase ascii wide
                        $string60_PowerUpSQL_offensive_tool_keyword = "Get-SQLServerPasswordHash" nocase ascii wide
                        $string61_PowerUpSQL_offensive_tool_keyword = "Get-SQLServerPriv" nocase ascii wide
                        $string62_PowerUpSQL_offensive_tool_keyword = "Get-SQLServiceAccount" nocase ascii wide
                        $string63_PowerUpSQL_offensive_tool_keyword = "Get-SQLServiceAccountPwHashes" nocase ascii wide
                        $string64_PowerUpSQL_offensive_tool_keyword = "Get-SQLSysadminCheck" nocase ascii wide
                        $string65_PowerUpSQL_offensive_tool_keyword = "Get-SQLTriggerDdl" nocase ascii wide
                        $string66_PowerUpSQL_offensive_tool_keyword = "Get-SQLTriggerDml" nocase ascii wide
                        $string67_PowerUpSQL_offensive_tool_keyword = "Install-SQLC2AgentLink" nocase ascii wide
                        $string68_PowerUpSQL_offensive_tool_keyword = "Install-SQLC2Server" nocase ascii wide
                        $string69_PowerUpSQL_offensive_tool_keyword = /Inveigh\-BruteForce\.ps1/ nocase ascii wide
                        $string70_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditDefaultLoginPw" nocase ascii wide
                        $string71_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivAutoExecSp" nocase ascii wide
                        $string72_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivCreateProcedure" nocase ascii wide
                        $string73_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivDbChaining" nocase ascii wide
                        $string74_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivImpersonateLogin" nocase ascii wide
                        $string75_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivServerLink" nocase ascii wide
                        $string76_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivTrustworthy" nocase ascii wide
                        $string77_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivXpDirtree" nocase ascii wide
                        $string78_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditPrivXpFileexit" nocase ascii wide
                        $string79_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditSQLiSpExecuteAs" nocase ascii wide
                        $string80_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditSQLiSpSigned" nocase ascii wide
                        $string81_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLAuditWeakLoginPw" nocase ascii wide
                        $string82_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLC2Command" nocase ascii wide
                        $string83_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLDumpInfo" nocase ascii wide
                        $string84_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLEscalatePriv" nocase ascii wide
                        $string85_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLImpersonateService" nocase ascii wide
                        $string86_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLImpersonateServiceCmd" nocase ascii wide
                        $string87_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmd" nocase ascii wide
                        $string88_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmdAgentJob" nocase ascii wide
                        $string89_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmdCLR" nocase ascii wide
                        $string90_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmdCOle" nocase ascii wide
                        $string91_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmdPython" nocase ascii wide
                        $string92_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLOSCmdR" nocase ascii wide
                        $string93_PowerUpSQL_offensive_tool_keyword = "Invoke-SqlServer-Persist-StartupSp" nocase ascii wide
                        $string94_PowerUpSQL_offensive_tool_keyword = "Invoke-SqlServer-Persist-TriggerLogon" nocase ascii wide
                        $string95_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLUncPathInjection" nocase ascii wide
                        $string96_PowerUpSQL_offensive_tool_keyword = "Invoke-SQLUncPathInjection" nocase ascii wide
                        $string97_PowerUpSQL_offensive_tool_keyword = "Invoke-TokenManipulation" nocase ascii wide
                        $string98_PowerUpSQL_offensive_tool_keyword = "NetSPI/Powershell-Modules" nocase ascii wide
                        $string99_PowerUpSQL_offensive_tool_keyword = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\UtilMan\.exe\\"\s\-Name\s/ nocase ascii wide
                        $string100_PowerUpSQL_offensive_tool_keyword = "PowerUpSQL" nocase ascii wide
                        $string101_PowerUpSQL_offensive_tool_keyword = "Register-SQLC2Agent" nocase ascii wide
                        $string102_PowerUpSQL_offensive_tool_keyword = "Remove-SQLC2Agent" nocase ascii wide
                        $string103_PowerUpSQL_offensive_tool_keyword = "Remove-SQLC2Command" nocase ascii wide
                        $string104_PowerUpSQL_offensive_tool_keyword = /SQLC2CMDS\.dll/ nocase ascii wide
                        $string105_PowerUpSQL_offensive_tool_keyword = "Uninstall-SQLC2AgentPs" nocase ascii wide
                        $string106_PowerUpSQL_offensive_tool_keyword = "Uninstall-SQLC2Server" nocase ascii wide
                        $string107_PowerUpSQL_offensive_tool_keyword = /writefile_bcpxpcmdshell\.sql/ nocase ascii wide
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