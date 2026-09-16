rule Trojan_Win32_RedLine_RPY_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}