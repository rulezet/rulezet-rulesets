rule Trojan_Win32_Stealerc_AMBH_MTB_2{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 45 ec 31 45 fc d3 ee 03 75 d8 81 3d ?? ?? ?? ?? 03 0b 00 00 } 		$a_01_1 = {4c 65 77 69 70 61 64 6f 6d 75 6e 69 66 75 63 20 68 69 68 6f 6b 65 79 69 6c 6f 20 66 65 78 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}