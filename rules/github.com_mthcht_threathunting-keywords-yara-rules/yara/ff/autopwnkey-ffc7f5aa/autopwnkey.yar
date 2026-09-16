rule AutoPwnKey
{
    meta:
        description = "Detection patterns for the tool 'AutoPwnKey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoPwnKey"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAddNewAdminUser\.ahk/ nocase ascii wide
                        $string2 = /\sAddScriptToRegistry\.ahk/ nocase ascii wide
                        $string3 = /\sAutoCrypt\.ahk/ nocase ascii wide
                        $string4 = /\sChromeDump\.ahk/ nocase ascii wide
                        $string5 = /\scmstp_uac\.ahk/ nocase ascii wide
                        $string6 = /\sDenyOutboundFirewall\.ahk/ nocase ascii wide
                        $string7 = /\sDomainTrustRecon\.ahk/ nocase ascii wide
                        $string8 = /\sEdgeDump\.ahk/ nocase ascii wide
                        $string9 = /\sEnumerateDCs\.ahk/ nocase ascii wide
                        $string10 = /\sIdentifyDomainAdmins\.ahk/ nocase ascii wide
                        $string11 = /\sIdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
                        $string12 = /\sKeyLogger\.ahk/ nocase ascii wide
                        $string13 = /\sPersistViaScheduledTask\.ahk/ nocase ascii wide
                        $string14 = /\sPortScanner\.ahk/ nocase ascii wide
                        $string15 = /\sReverseShell\.ahk/ nocase ascii wide
                        $string16 = /\sUnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
                        $string17 = /\sUnconstrainedDelegationCheck\.ahk/ nocase ascii wide
                        $string18 = /\sUnhookNTDLL\.ahk/ nocase ascii wide
                        $string19 = "\"ServiceName=\"\"bypassit\"" nocase ascii wide
                        $string20 = /\/AddNewAdminUser\.ahk/ nocase ascii wide
                        $string21 = /\/AddScriptToRegistry\.ahk/ nocase ascii wide
                        $string22 = /\/AutoCrypt\.ahk/ nocase ascii wide
                        $string23 = /\/AutoPwnKey\.git/ nocase ascii wide
                        $string24 = /\/c\snet\sgroup\s.{0,100}Domain\sAdmins.{0,100}\s\/domain\s\>\>\soutput\.txt/ nocase ascii wide
                        $string25 = /\/ChromeDump\.ahk/ nocase ascii wide
                        $string26 = /\/cmstp_uac\.ahk/ nocase ascii wide
                        $string27 = /\/DenyOutboundFirewall\.ahk/ nocase ascii wide
                        $string28 = /\/DomainTrustRecon\.ahk/ nocase ascii wide
                        $string29 = /\/EdgeDump\.ahk/ nocase ascii wide
                        $string30 = /\/EnumerateDCs\.ahk/ nocase ascii wide
                        $string31 = /\/IdentifyDomainAdmins\.ahk/ nocase ascii wide
                        $string32 = /\/IdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
                        $string33 = /\/KeyLogger\.ahk/ nocase ascii wide
                        $string34 = /\/PersistViaScheduledTask\.ahk/ nocase ascii wide
                        $string35 = /\/PortScanner\.ahk/ nocase ascii wide
                        $string36 = /\/ReverseShell\.ahk/ nocase ascii wide
                        $string37 = /\/UnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
                        $string38 = /\/UnhookNTDLL\.ahk/ nocase ascii wide
                        $string39 = /\\AddNewAdminUser\.ahk/ nocase ascii wide
                        $string40 = /\\AddScriptToRegistry\.ahk/ nocase ascii wide
                        $string41 = /\\AutoCrypt\.ahk/ nocase ascii wide
                        $string42 = /\\AutoPwnKey\-main/ nocase ascii wide
                        $string43 = /\\ChromeDump\.ahk/ nocase ascii wide
                        $string44 = /\\cmstp_uac\.ahk/ nocase ascii wide
                        $string45 = /\\Crypttest\\.{0,100}\.encrypted/ nocase ascii wide
                        $string46 = /\\DenyOutboundFirewall\.ahk/ nocase ascii wide
                        $string47 = /\\Documents\\Crypttest\\/ nocase ascii wide
                        $string48 = /\\DomainTrustRecon\.ahk/ nocase ascii wide
                        $string49 = /\\EdgeDump\.ahk/ nocase ascii wide
                        $string50 = /\\EnumerateDCs\.ahk/ nocase ascii wide
                        $string51 = /\\IdentifyDomainAdmins\.ahk/ nocase ascii wide
                        $string52 = /\\IdentifyGroupMembershipActiveUser\.ahk/ nocase ascii wide
                        $string53 = /\\KeyLogger\.ahk/ nocase ascii wide
                        $string54 = /\\PersistViaScheduledTask\.ahk/ nocase ascii wide
                        $string55 = /\\PortScanner\.ahk/ nocase ascii wide
                        $string56 = /\\ReverseShell\.ahk/ nocase ascii wide
                        $string57 = /\\UnconstrainedDelegationCheck\s\.ahk/ nocase ascii wide
                        $string58 = /\\UnconstrainedDelegationCheck\.ahk/ nocase ascii wide
                        $string59 = /\\UnhookNTDLL\.ahk/ nocase ascii wide
                        $string60 = "0d0b7a5276ebfefb28407800d2ba37f5102c9917cacaac5b265df55f95759b14" nocase ascii wide
                        $string61 = "2ffc8e93d89c9f9c090df5e44eb7921633c6954176b06183acbd459369a919b8" nocase ascii wide
                        $string62 = "63da55b370a27e54e02b3d7b56515734dd12a930faec455beaf2c6e9bcbfab32" nocase ascii wide
                        $string63 = "7b6b043f894bb0f34244c9cb88dc1cf801d16010817d51fe7c1f6be2af6b91bf" nocase ascii wide
                        $string64 = "91a579342f9fd24373e7d273db24aa0f936c9cb7929a3f0dcee357a84173e1eb" nocase ascii wide
                        $string65 = "9566f875d51e0259d3d64d6a20250ffaffd527e17e060cde0b77dea42a10a13e" nocase ascii wide
                        $string66 = "9fc04e375ecd2d91dff8a0cd64fc10852bdca276699fd6d633b4e5537b7d5c5a" nocase ascii wide
                        $string67 = "a83ba2c435fcf714eda4cc84cde9a72c8214157eba585b2debba0f9274af0e8f" nocase ascii wide
                        $string68 = /AutoCrypt_Password\.txt/ nocase ascii wide
                        $string69 = "AutoPwnKey Agent Manager" nocase ascii wide
                        $string70 = /AutoPwnKey\.AgentManager/ nocase ascii wide
                        $string71 = /autopwnkey\.db/ nocase ascii wide
                        $string72 = "AutoPwnKey-agent" nocase ascii wide
                        $string73 = "AutoPwnKey-server" nocase ascii wide
                        $string74 = "AutoPwnKey-server/logs" nocase ascii wide
                        $string75 = "b5df5bd38cb4be2db37d159e001de5e5b6e9bbfc0f0e90a59827fd6290a1f05f" nocase ascii wide
                        $string76 = "b7fa937e1b42914b6dee7a038520775e09532babd8c296a8e86db0faab66236c" nocase ascii wide
                        $string77 = "c2109f44079ae2c753b2f2763562c141d7db57a33649baa7086b204109a98d25" nocase ascii wide
                        $string78 = "c46f4d7407e46fd600a3e400128c22a599bf7152068af8304fbd47c91ca39698" nocase ascii wide
                        $string79 = "c9d16fdf0e5aa489bd8c6f0d930a8c25d9ad665583adb7780bc261b4df9c639c" nocase ascii wide
                        $string80 = "CroodSolutions/AutoPwnKey" nocase ascii wide
                        $string81 = /curl\s\-L\s\-o\sahk\.exe\shttps\:\/\/github\.com\/AutoHotkey\// nocase ascii wide
                        $string82 = "d15d3424eed0a69503213f2c7261d831f676b51383f4a10924bee81ce0e47d49" nocase ascii wide
                        $string83 = "deda1e50aa7963be239c0e43bb7dcd05014b1e048f89fe08f537ef0ce19afe58" nocase ascii wide
                        $string84 = /Desktop\\AutoCrypt_Password\.txt/ nocase ascii wide
                        $string85 = /DiscoverBasicHostRecon\.ahk/ nocase ascii wide
                        $string86 = "e6d5759ff74805dfb7e2b133493111a1a265e06d4dfcee80302048b6a173334a" nocase ascii wide
                        $string87 = "ef105cd1be00cf14b44173895a2610f5e5ed4d06390494be20bf7175215ea851" nocase ascii wide
                        $string88 = "KeyLogger data received" nocase ascii wide
                        $string89 = /Keylogger\sstarting\.\.\./ nocase ascii wide
                        $string90 = /Keylogger\sstopping\.\.\./ nocase ascii wide
                        $string91 = /keylogger_output_.{0,100}\.txt/ nocase ascii wide
                        $string92 = "Monitor KeyLogger output from a specific agent" nocase ascii wide
                        $string93 = /netsh\sadvfirewall\sfirewall\sadd\srule\s.{0,100}Deny\sOutbound\sfor\s/ nocase ascii wide
                        $string94 = /self\.keylogger_widget/ nocase ascii wide
                        $string95 = "Starting AddUserToAdminGroup for user:" nocase ascii wide
                        $string96 = "Starting AutoPwnKey Port Scanner at" nocase ascii wide
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