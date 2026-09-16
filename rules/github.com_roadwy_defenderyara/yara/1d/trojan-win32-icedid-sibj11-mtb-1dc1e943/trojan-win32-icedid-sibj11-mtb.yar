rule Trojan_Win32_IcedId_SIBJ11_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 6e 74 65 72 2e 70 64 62 } 		$a_03_1 = {8b 0f 81 c1 ?? ?? ?? ?? [0-10] 89 0f 83 c7 04 83 6c 24 ?? 01 [0-10] 0f 85 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}