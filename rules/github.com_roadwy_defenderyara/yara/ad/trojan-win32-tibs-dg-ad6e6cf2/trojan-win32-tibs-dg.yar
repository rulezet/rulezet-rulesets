rule Trojan_Win32_Tibs_DG{
	meta:
		description = "Trojan:Win32/Tibs.DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 14 8d 1c 18 8b 75 10 89 f7 c9 c2 10 00 8d 05 } 		$a_01_1 = {45 72 61 73 65 54 61 70 65 00 00 00 46 61 74 61 6c 45 78 69 74 00 47 44 49 33 32 2e 44 4c 4c 00 } 		$a_01_2 = {49 57 69 6e 64 6f 77 41 00 00 00 43 72 65 61 74 65 50 6f 70 75 70 4d 65 6e 75 00 57 49 4e 49 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}