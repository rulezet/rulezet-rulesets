rule Trojan_Win32_Emotetcrypt_RTH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_81_0 = {70 73 6f 6c 64 6b 6a 66 6e 62 73 76 63 79 75 64 69 62 6e 76 73 63 72 67 70 } 		$a_81_1 = {43 3a 5c 44 4c 4c 50 4f 52 54 41 42 4c 45 58 38 36 5c 33 32 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 33 32 73 6d 70 6c 2e 70 64 62 } 		$a_81_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_81_3 = {47 65 74 43 50 49 6e 66 6f } 	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=22
 
}