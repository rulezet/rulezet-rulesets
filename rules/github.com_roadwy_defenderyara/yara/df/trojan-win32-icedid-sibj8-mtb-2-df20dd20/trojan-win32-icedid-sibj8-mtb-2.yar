rule Trojan_Win32_IcedId_SIBJ8_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ8!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 61 6d 69 6c 79 77 6f 6e 64 65 72 2e 70 64 62 } 		$a_03_1 = {83 c1 04 89 4d ?? 81 7d 90 1b 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 90 08 60 01 8b 0d ?? ?? ?? ?? 03 4d 90 1b 00 8b 91 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 90 08 e0 02 8b 15 90 1b 08 81 c2 ?? ?? ?? ?? 89 15 90 1b 08 a1 90 1b 05 03 45 90 1b 00 8b 0d 90 1b 08 89 88 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}