rule Trojan_Win32_DarkComet_ADK_MTB_4{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ee 33 eb 23 e9 33 ee 03 fd 03 c7 8b f8 c1 e7 0c c1 e8 14 0b f8 03 f9 8b c7 8b 7a 08 03 3d 98 17 49 00 8b eb 33 e9 23 e8 33 eb 03 fd 03 f7 8b fe c1 e7 11 c1 ee 0f 0b fe 03 f8 8b f7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}