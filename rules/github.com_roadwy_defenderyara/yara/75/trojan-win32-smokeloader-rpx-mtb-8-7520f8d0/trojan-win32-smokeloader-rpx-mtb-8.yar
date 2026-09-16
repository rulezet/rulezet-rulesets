rule Trojan_Win32_SmokeLoader_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8 c1 e2 04 89 55 fc 8b 45 e4 01 45 fc 8b 4d f8 8b f1 c1 ee 05 03 75 e0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}