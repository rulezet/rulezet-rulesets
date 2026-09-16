rule rule_PetitPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PetitPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PetitPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PetitPotato_offensive_tool_keyword = /\sPetitPotato\.cpp/ nocase ascii wide
                        $string2_PetitPotato_offensive_tool_keyword = /\.exe\s3\scmd/ nocase ascii wide
                        $string3_PetitPotato_offensive_tool_keyword = /\/PetitPotato\.cpp/ nocase ascii wide
                        $string4_PetitPotato_offensive_tool_keyword = /\/PetitPotato\.git/ nocase ascii wide
                        $string5_PetitPotato_offensive_tool_keyword = /\/PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
                        $string6_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcAddUsersToFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string7_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcAddUsersToFileEx\swith\starget\spath\:\s/ nocase ascii wide
                        $string8_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcDecryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
                        $string9_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string10_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcDuplicateEncryptionInfoFile\swith\starget\spath\:/ nocase ascii wide
                        $string11_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcEncryptFileSrv\swith\starget\spath\:\s/ nocase ascii wide
                        $string12_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcFileKeyInfo\swith\starget\spath\:\s/ nocase ascii wide
                        $string13_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcFileKeyInfoEx\swith\starget\spath\:\s/ nocase ascii wide
                        $string14_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcGetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
                        $string15_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcOpenFileRaw\swith\starget\spath\:\s/ nocase ascii wide
                        $string16_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcQueryRecoveryAgents\swith\starget\spath\:\s/ nocase ascii wide
                        $string17_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcQueryUsersOnFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string18_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcRemoveUsersFromFile\swith\starget\spath\:\s/ nocase ascii wide
                        $string19_PetitPotato_offensive_tool_keyword = /\[\+\]\sInvoking\sEfsRpcSetEncryptedFileMetadata\swith\starget\spath\:\s/ nocase ascii wide
                        $string20_PetitPotato_offensive_tool_keyword = /\[\+\]\sMalicious\snamed\spipe\srunning\son\s/ nocase ascii wide
                        $string21_PetitPotato_offensive_tool_keyword = /\\\\localhost\/pipe\/petit\\/ nocase ascii wide
                        $string22_PetitPotato_offensive_tool_keyword = /\\\\pipe\\\\petit\\\\pipe\\\\srvsvc/ nocase ascii wide
                        $string23_PetitPotato_offensive_tool_keyword = /\\C\$\\wh0nqs\.txt\./ nocase ascii wide
                        $string24_PetitPotato_offensive_tool_keyword = /\\petit\\pipe\\srvsvc/ nocase ascii wide
                        $string25_PetitPotato_offensive_tool_keyword = /\\PetitPotato\.cpp/ nocase ascii wide
                        $string26_PetitPotato_offensive_tool_keyword = /\\PetitPotato\.log/ nocase ascii wide
                        $string27_PetitPotato_offensive_tool_keyword = /\\petitpotato\.obj/ nocase ascii wide
                        $string28_PetitPotato_offensive_tool_keyword = /\\petitpotato\.pdb/ nocase ascii wide
                        $string29_PetitPotato_offensive_tool_keyword = /\\PetitPotato\.sln/ nocase ascii wide
                        $string30_PetitPotato_offensive_tool_keyword = /\\PetitPotato\.tlog/ nocase ascii wide
                        $string31_PetitPotato_offensive_tool_keyword = /\\PetitPotato\.vcxproj/ nocase ascii wide
                        $string32_PetitPotato_offensive_tool_keyword = /\\petitpotato\\x64\\/ nocase ascii wide
                        $string33_PetitPotato_offensive_tool_keyword = /\\PetitPotato\-1\.0\.0\.zip/ nocase ascii wide
                        $string34_PetitPotato_offensive_tool_keyword = /\\PetitPotato\-1\.0\.0\\/ nocase ascii wide
                        $string35_PetitPotato_offensive_tool_keyword = "A315E53B-397A-4074-B988-535A100D45DC" nocase ascii wide
                        $string36_PetitPotato_offensive_tool_keyword = "e55c85d7da9a60ed31867b421961b3503df0b464e068e584fccc20892b05bef2" nocase ascii wide
                        $string37_PetitPotato_offensive_tool_keyword = "eb760ea670e63083e0fef40c12861c6459ebf28b86129c8d3fa200714b2a0b02" nocase ascii wide
                        $string38_PetitPotato_offensive_tool_keyword = "PetitPotam bypass via RPC_C_AUTHN_LEVEL_PKT_PRIVACY" nocase ascii wide
                        $string39_PetitPotato_offensive_tool_keyword = "PetitPotato 3 cmd" nocase ascii wide
                        $string40_PetitPotato_offensive_tool_keyword = /PetitPotato\.Build\.CppClean\.log\,/ nocase ascii wide
                        $string41_PetitPotato_offensive_tool_keyword = /PetitPotato\.exe/ nocase ascii wide
                        $string42_PetitPotato_offensive_tool_keyword = /PetitPotato\.lastbuildstate/ nocase ascii wide
                        $string43_PetitPotato_offensive_tool_keyword = "wh0amitz/PetitPotato" nocase ascii wide

    condition:
        any of them
}