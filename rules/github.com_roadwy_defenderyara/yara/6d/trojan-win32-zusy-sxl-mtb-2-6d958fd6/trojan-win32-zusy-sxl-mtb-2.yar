rule Trojan_Win32_Zusy_SXL_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.SXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 55 d4 0f af 55 dc 89 55 dc c7 45 c4 ?? ?? ?? ?? 8b 45 c4 0f af 45 d4 8b 4d dc 2b c8 89 4d dc eb } 		$a_03_1 = {8b 45 e0 83 c0 03 89 45 e0 8b 4d a8 03 4d e4 8b 55 e0 8a 82 ?? ?? ?? ?? 88 01 eb } 		$a_01_2 = {4d 73 69 50 72 65 76 69 65 77 42 69 6c 6c 62 6f 61 72 64 57 } 	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=10
 
}