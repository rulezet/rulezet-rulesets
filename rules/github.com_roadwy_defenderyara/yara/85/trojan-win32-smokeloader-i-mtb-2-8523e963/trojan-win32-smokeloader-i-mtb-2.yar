rule Trojan_Win32_SmokeLoader_I_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 45 fc d3 ef 03 7d d4 81 3d f4 ec 41 02 } 		$a_03_1 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 ?? ?? ?? ?? ff 4d e8 0f } 		$a_01_2 = {03 7d e4 8b 45 e0 31 45 fc 33 7d fc 81 3d f4 ec 41 02 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}