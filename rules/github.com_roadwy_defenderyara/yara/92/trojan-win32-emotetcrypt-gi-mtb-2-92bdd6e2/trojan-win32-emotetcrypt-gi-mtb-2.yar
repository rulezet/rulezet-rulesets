rule Trojan_Win32_Emotetcrypt_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b ?? ?? 8b ?? ?? ?? 8b ?? ?? 8b ?? ?? ?? ff 15 } 		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } 		$a_02_2 = {83 c4 0c 8b ?? ?? 83 ?? 28 89 ?? ?? eb } 		$a_00_3 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc } 		$a_01_4 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 44 00 4c 00 4c 00 } 		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*10+(#a_02_2  & 1)*1+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}