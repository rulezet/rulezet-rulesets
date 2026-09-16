rule Trojan_Win32_SmokeLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 c5 89 44 24 14 33 44 24 20 33 c8 8d 44 24 28 89 4c 24 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}