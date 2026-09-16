rule Trojan_Win32_SmokeLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 c6 89 45 fc 2b f8 8b 45 cc 29 45 f8 83 6d e0 01 0f 85 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}