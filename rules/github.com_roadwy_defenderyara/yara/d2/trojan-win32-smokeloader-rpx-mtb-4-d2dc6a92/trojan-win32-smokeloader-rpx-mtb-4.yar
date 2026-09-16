rule Trojan_Win32_SmokeLoader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 75 05 74 03 e3 1c 2c 8b 1c 24 83 c4 04 eb 0a 08 81 eb dc 32 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}