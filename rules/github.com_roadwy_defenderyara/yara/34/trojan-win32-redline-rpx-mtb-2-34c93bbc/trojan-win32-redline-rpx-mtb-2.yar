rule Trojan_Win32_RedLine_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 20 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}