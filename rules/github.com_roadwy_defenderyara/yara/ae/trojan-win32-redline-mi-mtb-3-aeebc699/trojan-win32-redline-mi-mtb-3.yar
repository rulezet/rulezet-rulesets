rule Trojan_Win32_Redline_MI_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 6c 24 10 89 5c 24 18 8b 44 24 14 01 44 24 18 8b 44 24 24 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b f7 } 		$a_03_1 = {c1 ee 05 03 74 24 34 8b 44 24 20 31 44 24 10 81 3d f4 ?? ?? ?? ?? 01 00 00 75 [0-15] 8b 4c 24 10 33 ce 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 30 29 44 24 14 83 6c 24 2c 01 8b 54 24 28 0f 85 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}