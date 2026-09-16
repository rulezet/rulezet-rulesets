rule Trojan_Win32_IcedId_PK_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c2 2b d8 83 c3 1e 8b 44 24 18 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 38 a1 ?? ?? ?? ?? 8b 7c 24 18 2b c6 03 d0 83 c7 04 ff 4c 24 1c 89 54 24 ?? 89 7c 24 ?? 0f } 		$a_01_1 = {5c 53 74 65 70 5c 53 68 6f 65 5c 57 61 76 65 5c 70 75 6c 6c 5c 41 6c 6c 6f 77 5c 63 6f 6e 64 69 74 69 6f 6e 5c 63 6f 70 79 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}