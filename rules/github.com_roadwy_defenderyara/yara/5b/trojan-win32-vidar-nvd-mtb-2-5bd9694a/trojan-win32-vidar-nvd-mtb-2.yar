rule Trojan_Win32_Vidar_NVD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 05 36 2d 40 00 89 45 f8 b9 ?? ?? ?? ?? 6b d1 00 8b 45 f8 8b 0c 10 89 4d f4 8b 55 f4 c1 e2 02 52 b8 ?? ?? ?? ?? d1 e0 03 45 f8 50 8b 4d 0c 51 e8 ?? ?? ?? ?? 83 c4 0c ba ?? ?? ?? ?? c1 e2 00 8b 45 f8 8b 0c 10 89 4d f0 } 		$a_01_1 = {41 48 66 39 34 41 75 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}