rule Trojan_Win32_Glupteba_KM_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8d 4c 24 ?? 51 8d 54 24 ?? 52 50 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 60 0e 00 00 75 0c ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 c7 08 83 ee 01 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}