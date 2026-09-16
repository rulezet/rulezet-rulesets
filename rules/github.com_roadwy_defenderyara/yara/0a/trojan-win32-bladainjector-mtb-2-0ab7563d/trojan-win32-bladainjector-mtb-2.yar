rule Trojan_Win32_BladaInjector_MTB_2{
	meta:
		description = "Trojan:Win32/BladaInjector!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {28 22 00 00 0a 1f 0c 8d 10 00 00 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 25 } 		$a_02_1 = {28 82 00 00 0a 28 ?? ?? 00 06 6f ?? ?? 00 0a 13 ?? 11 ?? 20 ?? ?? 00 00 28 ?? ?? 00 06 6f ?? ?? 00 0a 13 ?? 2b } 		$a_02_2 = {28 52 00 00 06 6f 85 00 00 0a 13 ?? 73 ?? 00 00 06 80 ?? 00 00 04 11 ?? 14 1f ?? 8d ?? 00 00 01 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}