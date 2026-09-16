rule Trojan_Win32_AproposMedia{
	meta:
		description = "Trojan:Win32/AproposMedia,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 70 72 6f 70 6f 73 43 6c 69 65 6e 74 55 6e 49 6e 73 74 61 6c 6c 65 72 49 73 52 75 6e 6e 69 6e 67 } 		$a_01_1 = {41 70 72 6f 70 6f 73 43 6c 69 65 6e 74 54 65 72 6d 69 6e 61 74 65 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 70 72 6f 70 6f 73 5c 43 6c 69 65 6e 74 } 		$a_01_3 = {41 70 72 6f 70 6f 73 55 6e 69 6e 73 74 2e 69 6e 69 } 		$a_01_4 = {61 64 63 68 61 6e 6e 65 6c 2e 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=9
 
}