rule Trojan_Win32_Meralifea_A{
	meta:
		description = "Trojan:Win32/Meralifea.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 70 69 20 } 		$a_01_1 = {66 81 39 4e 45 } 		$a_01_2 = {45 77 72 6b } 		$a_80_3 = {5c 75 73 62 64 64 67 68 63 69 } 		$a_80_4 = {5c 55 73 62 67 4b 72 6e 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=5
 
}