rule rule_BackupCreds_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BackupCreds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupCreds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BackupCreds_offensive_tool_keyword = /\sbackupcreds\.exe/ nocase ascii wide
                        $string2_BackupCreds_offensive_tool_keyword = /\/backupcreds\.exe/ nocase ascii wide
                        $string3_BackupCreds_offensive_tool_keyword = /\/BackupCreds\.git/ nocase ascii wide
                        $string4_BackupCreds_offensive_tool_keyword = /\[\!\]\sCredBackupCredentials\(/ nocase ascii wide
                        $string5_BackupCreds_offensive_tool_keyword = /\\BackupCreds\.csproj/ nocase ascii wide
                        $string6_BackupCreds_offensive_tool_keyword = /\\backupcreds\.exe/ nocase ascii wide
                        $string7_BackupCreds_offensive_tool_keyword = /\\backupcreds\.sln/ nocase ascii wide
                        $string8_BackupCreds_offensive_tool_keyword = /\\backupcreds\\Program\.cs/ nocase ascii wide
                        $string9_BackupCreds_offensive_tool_keyword = /\\BackupCreds\-main/ nocase ascii wide
                        $string10_BackupCreds_offensive_tool_keyword = /\]\sEnjoy\syour\screds\!\sReverting\sto\sself/ nocase ascii wide
                        $string11_BackupCreds_offensive_tool_keyword = "7943C5FF-C219-4E0B-992E-0ECDEB2681F3" nocase ascii wide
                        $string12_BackupCreds_offensive_tool_keyword = "leftp/BackupCreds" nocase ascii wide
                        $string13_BackupCreds_offensive_tool_keyword = "namespace BackupCreds" nocase ascii wide
                        $string14_BackupCreds_offensive_tool_keyword = /using\sstatic\sBackupCreds\.Interop/ nocase ascii wide

    condition:
        any of them
}