rule Trojan_Win32_RedLine_RPX_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 51 59 58 88 04 0b eb 05 d1 5d 29 f5 38 50 b8 b7 00 00 00 eb 19 4c 6f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}