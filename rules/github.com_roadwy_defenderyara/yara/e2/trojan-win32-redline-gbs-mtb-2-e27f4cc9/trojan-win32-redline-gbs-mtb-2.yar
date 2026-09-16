rule Trojan_Win32_Redline_GBS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 37 46 3b f3 72 } 		$a_03_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 } 		$a_03_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1) >=11
 
}