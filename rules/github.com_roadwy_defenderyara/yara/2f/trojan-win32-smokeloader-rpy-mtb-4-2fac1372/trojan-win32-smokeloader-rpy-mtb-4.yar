rule Trojan_Win32_SmokeLoader_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 60 02 00 00 ea 13 30 0a c7 84 24 74 02 00 00 0a 4b 19 39 c7 84 24 04 03 00 00 3e 5c d5 18 c7 84 24 c8 01 00 00 e9 d6 86 0e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}