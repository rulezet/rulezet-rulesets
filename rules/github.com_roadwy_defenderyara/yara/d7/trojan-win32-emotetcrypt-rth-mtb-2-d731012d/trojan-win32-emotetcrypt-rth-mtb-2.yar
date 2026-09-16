rule Trojan_Win32_Emotetcrypt_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4d 61 6c 66 6f 72 6d 65 64 20 4a 50 32 20 66 69 6c 65 20 66 6f 72 6d 61 74 } 		$a_81_1 = {5a 3a 5c 63 72 5c 63 72 79 70 74 65 72 34 5c 62 61 6c 6c 61 73 74 5c 33 5c 6f 70 65 6e 6a 70 32 5c 6f 70 6a 5f 69 6e 74 6d 61 74 68 2e 68 } 		$a_81_2 = {43 4f 4d 4d 4f 4e 5f 43 42 4c 4b 5f 44 41 54 41 5f 45 58 54 52 41 } 		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_81_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}