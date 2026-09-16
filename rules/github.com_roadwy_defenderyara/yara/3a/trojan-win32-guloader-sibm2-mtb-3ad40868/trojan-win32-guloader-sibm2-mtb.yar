rule Trojan_Win32_GuLoader_SIBM2_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 9d 81 34 17 ?? ?? ?? ?? [0-30] 83 c2 04 [0-30] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-30] ff e7 } 		$a_00_1 = {56 00 61 00 72 00 69 00 61 00 6e 00 74 00 66 00 75 00 6e 00 6b 00 74 00 69 00 6f 00 6e 00 73 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}