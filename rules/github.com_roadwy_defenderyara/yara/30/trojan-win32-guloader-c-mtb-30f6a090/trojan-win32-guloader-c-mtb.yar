rule Trojan_Win32_Guloader_C_MTB{
	meta:
		description = "Trojan:Win32/Guloader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 6e 6b 61 73 73 65 72 69 6e 67 65 6e 73 2e 69 6e 69 } 		$a_81_1 = {67 75 73 6c 65 65 2e 6c 74 61 } 		$a_81_2 = {73 74 72 61 6b 73 61 66 73 6b 72 69 76 6e 69 6e 67 65 72 6e 65 2e 73 61 6b } 		$a_81_3 = {73 6b 61 74 74 65 70 72 6f 63 65 6e 74 73 5c 68 65 6c 64 74 65 72 6e 69 6e 67 65 6e 73 } 		$a_81_4 = {6d 69 6e 69 72 6f 62 6f 74 2e 75 6e 69 } 	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}