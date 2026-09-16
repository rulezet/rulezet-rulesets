rule Trojan_Win32_IcedId_SIBJ12_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 75 64 6d 69 6e 65 2e 70 64 62 } 		$a_03_1 = {03 cd 89 4c 24 ?? 8b 29 [0-30] 8b 4c 24 90 1b 00 81 c5 ?? ?? ?? ?? [0-10] 89 29 [0-30] 8b 6c 24 ?? [0-10] 83 c5 04 [0-10] 89 6c 24 90 1b 06 [0-10] 81 fd ?? ?? ?? ?? 0f 82 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}