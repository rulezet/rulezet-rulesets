rule Trojan_Win32_Remcos_RPX_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 4d f8 8d 14 30 8b 45 fc d3 ee 8b 4d d0 03 c1 33 c2 03 75 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}