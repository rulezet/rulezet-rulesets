rule Trojan_Win32_Vidar_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.AB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 8b 4d f8 8d 04 3b d3 ef 89 45 e0 c7 05 ec bc 49 02 ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc } 		$a_01_1 = {72 6f 62 75 62 69 7a 65 6b 69 5f 6a 6f 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}