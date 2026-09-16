rule Trojan_Win32_Azorult_RTH_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d ?? 50 03 fe 8d 45 ?? 33 cf 50 c7 05 ?? b4 21 e1 c5 } 		$a_03_1 = {b8 2c 19 00 00 e8 ?? ?? ?? ?? 56 33 f6 81 3d ?? ?? ?? ?? 77 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}