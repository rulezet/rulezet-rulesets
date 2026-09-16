rule Trojan_Win32_EyeStye_11{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 65 41 5a 2e 64 6c 6c 00 } 		$a_01_1 = {76 61 72 20 5f 61 61 7a 5f 72 65 7a 20 3d 20 31 3b } 		$a_01_2 = {6a 00 6a 00 6a 03 6a 00 6a 00 68 bb 01 00 00 8d 4d c0 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}