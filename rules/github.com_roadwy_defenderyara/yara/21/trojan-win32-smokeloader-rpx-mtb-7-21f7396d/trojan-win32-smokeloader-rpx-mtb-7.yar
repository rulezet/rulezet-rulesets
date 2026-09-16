rule Trojan_Win32_SmokeLoader_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 f0 8b 45 f8 33 45 f0 2b f0 89 45 f8 8b c6 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f4 8d 04 33 89 45 e8 8b c6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}