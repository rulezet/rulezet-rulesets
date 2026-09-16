rule Trojan_Win32_SmokeLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}