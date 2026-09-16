rule Trojan_Win32_Vidar_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 2c 8d 44 24 14 c7 05 24 0f 4d 00 ee 3d ea f4 e8 ?? ff ff ff 8b 44 24 20 31 44 24 10 8b 54 24 10 31 54 24 14 81 3d 2c 0f 4d 00 13 02 00 00 75 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}