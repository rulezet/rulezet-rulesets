rule Trojan_Win32_IcedId_SIBJ13_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 68 69 65 66 4c 65 67 2e 70 64 62 } 		$a_03_1 = {89 3e 83 c6 04 [0-10] 83 6c 24 ?? 01 89 74 24 ?? 90 18 [0-60] 8b 54 24 90 1b 02 8b 3a [0-50] 8b 74 24 90 1b 02 81 c7 ?? ?? ?? ?? [0-10] 89 3e } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}