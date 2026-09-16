rule Trojan_Win32_RedLine_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7c 24 10 c7 44 24 1c 00 00 00 00 8b 44 24 28 01 44 24 1c 8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b 54 24 14 d3 ea 8b cb 8d 44 24 24 89 54 24 24 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}