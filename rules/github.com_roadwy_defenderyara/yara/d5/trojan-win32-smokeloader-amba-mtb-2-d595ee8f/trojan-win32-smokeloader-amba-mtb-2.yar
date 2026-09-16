rule Trojan_Win32_Smokeloader_AMBA_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 7d f0 8b d6 d3 ea 8d 04 37 89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec } 		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d ?? ?? ?? ?? 21 01 00 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}