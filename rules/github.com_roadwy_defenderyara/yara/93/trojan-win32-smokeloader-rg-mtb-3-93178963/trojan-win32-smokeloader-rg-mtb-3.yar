rule Trojan_Win32_SmokeLoader_RG_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}