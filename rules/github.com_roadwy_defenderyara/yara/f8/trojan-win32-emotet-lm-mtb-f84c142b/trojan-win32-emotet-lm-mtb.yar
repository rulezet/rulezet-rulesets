rule Trojan_Win32_Emotet_LM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 64 24 00 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 30 40 3b c7 } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}