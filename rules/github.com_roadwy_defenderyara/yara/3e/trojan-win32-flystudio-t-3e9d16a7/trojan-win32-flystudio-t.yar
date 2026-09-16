rule Trojan_Win32_FlyStudio_T{
	meta:
		description = "Trojan:Win32/FlyStudio.T,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 69 67 66 78 74 72 61 79 } 		$a_01_1 = {5c 7a 68 75 6f 6d 69 61 6e 2e 6a 70 67 } 		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } 		$a_01_3 = {45 52 61 77 53 6f 63 6b } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=9
 
}