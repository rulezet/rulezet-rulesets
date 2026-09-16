rule Trojan_Win32_BladaInjector_MTB{
	meta:
		description = "Trojan:Win32/BladaInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {28 02 00 00 0a a2 25 1a 11 04 a2 28 03 00 00 0a 6f 04 00 00 0a 13 05 28 05 00 00 0a 72 ?? 35 00 70 18 17 8d 01 00 00 01 25 16 11 05 16 11 05 8e 69 28 06 00 00 0a a2 28 07 00 00 0a 74 02 00 00 01 13 06 11 06 6f 08 00 00 0a 16 9a 13 07 73 01 00 00 06 13 08 11 07 19 8d 01 00 00 01 25 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}