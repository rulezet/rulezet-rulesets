rule Trojan_Win32_SmokeLoader_A_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 54 24 18 8b 4c 24 1c d3 ea 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 20 31 44 24 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}