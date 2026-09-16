rule Trojan_Win32_Azorult_RPY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}