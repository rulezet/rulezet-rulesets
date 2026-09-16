rule Trojan_Win32_SmokeLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 45 fc 89 5d f4 8b 45 e8 01 45 f4 8b 45 d0 90 01 45 f4 8b 45 f4 89 45 ec 8b 4d f0 8b c6 d3 e8 8b 4d ec 31 4d fc 03 45 cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}