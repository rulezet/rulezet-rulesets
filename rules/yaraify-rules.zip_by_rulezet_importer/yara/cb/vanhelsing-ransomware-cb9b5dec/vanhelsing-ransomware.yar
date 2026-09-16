rule VanHelsing_Ransomware {
    meta:
        description = "Detects VanHelsing Ransomware using file markers and behaviors"
        author = "Vasilis Orlof"
        reference = "https://research.checkpoint.com/2025/vanhelsing-new-raas-in-town/"
        date = "2025-03-27"
        hash1 = "79106dd259ba5343202c2f669a0a61b10adfadff" 
        hash2 = "e683bfaeb1a695ff9ef1759cf1944fa3bb3b6948" 
        yarahub_uuid = "e57e6137-99e4-46f7-ba7b-131490fdb0d8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6f6cc222f3a1886191407a0eaa8b7b83"
    
    strings:
                $filename1 = "vhlocker.png" ascii wide
        $filename2 = "vhlocker.ico" ascii wide
        
                $note1 = "Your network has been breached" ascii wide
        $note2 = "README.txt" ascii wide
        
                $arg1 = "--no-mounted" ascii wide
        $arg2 = "--no-network" ascii wide
        $arg3 = "--spread-smb" ascii wide
        $arg4 = "--Silent" ascii wide
        $arg5 = "--skipshadow" ascii wide
        
                $pdb = "1-locker.pdb" ascii wide
        
                $dir1 = "C:\\Windows\\Web" ascii wide
        $cmd1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where" ascii wide
        
                $mutex = "Global\\VanHelsing" ascii wide
        
                $encmarker1 = "---key---" ascii wide
        $encmarker2 = "---endkey---" ascii wide
        $encmarker3 = "---nonce---" ascii wide
        $encmarker4 = "---endnonce---" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and         (
                        (any of ($filename*)) or
            (3 of ($arg*)) or
                        (2 of ($encmarker*)) or
                        ($pdb) or
            ($mutex) or
                        ($cmd1) or
                        (($dir1) and ($note1 or $note2))
        )
}