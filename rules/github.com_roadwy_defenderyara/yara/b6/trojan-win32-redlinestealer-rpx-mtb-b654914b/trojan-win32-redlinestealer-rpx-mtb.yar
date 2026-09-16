rule Trojan_Win32_RedlineStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f3 33 d8 8b c6 f6 17 8b f0 8b c0 33 de 33 c0 8b c6 33 f3 8b f3 33 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}