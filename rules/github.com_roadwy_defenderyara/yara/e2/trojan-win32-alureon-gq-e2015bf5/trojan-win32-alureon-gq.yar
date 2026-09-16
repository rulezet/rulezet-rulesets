rule Trojan_Win32_Alureon_GQ{
	meta:
		description = "Trojan:Win32/Alureon.GQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 66 69 67 77 72 69 74 65 00 } 		$a_01_1 = {00 64 6f 77 6e 6c 6f 61 64 00 } 		$a_01_2 = {00 6c 6f 61 64 6d 6f 64 75 6c 65 00 } 		$a_01_3 = {00 63 6d 64 64 65 6c 61 79 00 } 		$a_01_4 = {26 61 69 64 3d 25 73 26 69 64 3d 25 73 26 6f 73 3d 25 73 5f 25 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4) >=5
 
}