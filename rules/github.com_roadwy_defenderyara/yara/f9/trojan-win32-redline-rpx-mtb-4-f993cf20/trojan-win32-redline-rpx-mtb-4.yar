rule Trojan_Win32_RedLine_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b d6 d3 ea 03 54 24 30 89 54 24 14 8b 44 24 20 31 44 24 10 8b 44 24 10 33 44 24 14 2b f8 89 44 24 10 8d 44 24 24 89 7c 24 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}