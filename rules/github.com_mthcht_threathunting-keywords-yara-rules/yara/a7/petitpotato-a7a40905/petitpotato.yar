rule PetitPotato
{
    meta:
        description = "Detection patterns for the tool 'PetitPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PetitPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPetitPotato\.cpp/ nocase ascii wide
                        $string2 = /\.exe\s3\scmd/ nocase ascii wide
                        $string3 = /\/PetitPotato\.cpp/ nocase ascii wide
                        $string4 = /\/PetitPotato\.git/ nocase ascii wide
                        $string5 = /\/PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
                        $string6 = /\[\+\]\sInvoking\sEfsRpcAddUsersToFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string7 = /\[\+\]\sInvoking\sEfsRpcAddUsersToFileEx\swith\starget\spath\:\s/ nocase ascii wide
                        $string8 = /\[\+\]\sInvoking\sEfsRpcDecryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
                        $string9 = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string10 = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:/ nocase ascii wide
                        $string11 = /\[\+\]\sInvoking\sEfsRpcEncryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
                        $string12 = /\[\+\]\sInvoking\sEfsRpcFileKeyInfo\swith\starget\spath\:\s/ nocase ascii wide
                        $string13 = /\[\+\]\sInvoking\sEfsRpcFileKeyInfoEx\swith\starget\spath\:\s/ nocase ascii wide
                        $string14 = /\[\+\]\sInvoking\sEfsRpcGetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
                        $string15 = /\[\+\]\sInvoking\sEfsRpcOpenFileRaw\swith\starget\spath\:\s/ nocase ascii wide
                        $string16 = /\[\+\]\sInvoking\sEfsRpcQueryRecoveryAgents\swith\starget\spath\:\s/ nocase ascii wide
                        $string17 = /\[\+\]\sInvoking\sEfsRpcQueryUsersOnFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string18 = /\[\+\]\sInvoking\sEfsRpcRemoveUsersFromFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string19 = /\[\+\]\sInvoking\sEfsRpcSetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
                        $string20 = /\[\+\]\sMalicious\snamed\spipe\srunning\son\s/ nocase ascii wide
                        $string21 = /\\\\localhost\/pipe\/petit\\/ nocase ascii wide
                        $string22 = /\\\\pipe\\\\petit\\\\pipe\\\\srvsvc/ nocase ascii wide
                        $string23 = /\\C\$\\wh0nqs\.txt\./ nocase ascii wide
                        $string24 = /\\petit\\pipe\\srvsvc/ nocase ascii wide
                        $string25 = /\\PetitPotato\.cpp/ nocase ascii wide
                        $string26 = /\\PetitPotato\.log/ nocase ascii wide
                        $string27 = /\\petitpotato\.obj/ nocase ascii wide
                        $string28 = /\\petitpotato\.pdb/ nocase ascii wide
                        $string29 = /\\PetitPotato\.sln/ nocase ascii wide
                        $string30 = /\\PetitPotato\.tlog/ nocase ascii wide
                        $string31 = /\\PetitPotato\.vcxproj/ nocase ascii wide
                        $string32 = /\\petitpotato\\x64\\/ nocase ascii wide
                        $string33 = /\\PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
                        $string34 = /\\PetitPotato\-1\.0\.0\\/ nocase ascii wide
                        $string35 = "A315E53B-397A-4074-B988-535A100D45DC" nocase ascii wide
                        $string36 = "e55c85d7da9a60ed31867b421961b3503df0b464e068e584fccc20892b05bef2" nocase ascii wide
                        $string37 = "eb760ea670e63083e0fef40c12861c6459ebf28b86129c8d3fa200714b2a0b02" nocase ascii wide
                        $string38 = "PetitPotam bypass via RPC_C_AUTHN_LEVEL_PKT_PRIVACY" nocase ascii wide
                        $string39 = "PetitPotato 3 cmd" nocase ascii wide
                        $string40 = /PetitPotato\.Build\.CppClean\.log\,/ nocase ascii wide
                        $string41 = /PetitPotato\.exe/ nocase ascii wide
                        $string42 = /PetitPotato\.lastbuildstate/ nocase ascii wide
                        $string43 = "wh0amitz/PetitPotato" nocase ascii wide
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