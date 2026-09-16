rule CN_Honker_passwd_dict_3389 {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file 3389.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "2897e909e48a9f56ce762244c3a3e9319e12362f"
        id = "9418f0e5-7bf0-5df3-8857-dea90fae5a54"
    strings:
        $s0 = "654321" fullword ascii 
        $s1 = "admin123" fullword ascii 
        $s2 = "admin123456" fullword ascii 
        $s3 = "administrator" fullword ascii  
        $s4 = "passwd" fullword ascii  
        $s5 = "password" fullword ascii  
        $s7 = "12345678" fullword ascii 
    condition:
        filesize < 1KB and all of them
}