rule Trojan_Win32_Emotetcrypt_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {4f 30 21 66 3f 63 7a 6d 3f 39 63 68 68 75 6d 29 69 66 24 24 5a 46 30 36 63 69 2a 40 38 32 3c 33 4a 49 3f 6f 4b 62 7a 5e 34 21 50 63 44 75 70 76 68 61 6b 49 66 62 56 43 7a 4a 61 77 65 62 49 31 6a 79 47 79 6a 68 2a 6c 50 62 65 76 30 73 31 4d 6b 61 71 68 53 6e 3c 41 64 29 29 61 61 53 24 78 34 2b 3f 43 3c 63 74 30 31 2a 3c 5a 69 } 		$a_03_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 2b d1 8a 0c 1a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 } 	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}