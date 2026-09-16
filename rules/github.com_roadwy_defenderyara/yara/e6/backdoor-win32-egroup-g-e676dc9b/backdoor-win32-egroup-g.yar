rule Backdoor_Win32_EGroup_G{
	meta:
		description = "Backdoor:Win32/EGroup.G,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 45 47 45 78 63 65 70 74 69 6f 6e 3a 3a 43 45 47 45 78 63 65 70 74 69 6f 6e 28 29 20 65 6e 74 65 72 65 64 } 		$a_01_1 = {65 67 68 6f 73 74 5f } 		$a_01_2 = {64 6f 72 61 73 6d 6f 6e 69 74 6f 72 } 		$a_01_3 = {69 6e 73 74 61 6e 74 20 61 63 63 65 73 73 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=9
 
}