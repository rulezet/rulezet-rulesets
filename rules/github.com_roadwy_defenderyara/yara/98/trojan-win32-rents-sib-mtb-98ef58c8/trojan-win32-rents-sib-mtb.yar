rule Trojan_Win32_REntS_SIB_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 6e 00 61 00 6d 00 65 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 3e 00 } 		$a_03_1 = {0f b6 00 0f b6 4c 24 ?? 33 c1 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b d1 48 8b ca 0f b6 c9 81 e1 ?? ?? ?? ?? 33 c1 48 8b 4c 24 90 1b 02 88 01 } 		$a_03_2 = {0f be 04 01 35 ?? ?? ?? ?? 88 44 24 ?? 48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 89 44 24 ?? 48 83 7c 24 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}