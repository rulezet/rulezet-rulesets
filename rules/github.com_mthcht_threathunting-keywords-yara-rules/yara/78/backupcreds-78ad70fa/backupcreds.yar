rule BackupCreds
{
    meta:
        description = "Detection patterns for the tool 'BackupCreds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupCreds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbackupcreds\.exe/ nocase ascii wide
                        $string2 = /\/backupcreds\.exe/ nocase ascii wide
                        $string3 = /\/BackupCreds\.git/ nocase ascii wide
                        $string4 = /\[\!\]\sCredBackupCredentials\(/ nocase ascii wide
                        $string5 = /\\BackupCreds\.csproj/ nocase ascii wide
                        $string6 = /\\backupcreds\.exe/ nocase ascii wide
                        $string7 = /\\backupcreds\.sln/ nocase ascii wide
                        $string8 = /\\backupcreds\\Program\.cs/ nocase ascii wide
                        $string9 = /\\BackupCreds\-main/ nocase ascii wide
                        $string10 = /\]\sEnjoy\syour\screds\!\sReverting\sto\sself/ nocase ascii wide
                        $string11 = "7943C5FF-C219-4E0B-992E-0ECDEB2681F3" nocase ascii wide
                        $string12 = "leftp/BackupCreds" nocase ascii wide
                        $string13 = "namespace BackupCreds" nocase ascii wide
                        $string14 = /using\sstatic\sBackupCreds\.Interop/ nocase ascii wide

    condition:
        any of them
}