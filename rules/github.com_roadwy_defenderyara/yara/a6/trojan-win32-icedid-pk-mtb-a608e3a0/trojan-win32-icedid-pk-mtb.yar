rule Trojan_Win32_IcedId_PK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 ff 8b f0 33 c9 8b 84 ?? ?? ?? ?? ?? ba ?? ?? ?? ?? f7 e2 03 c7 89 84 ?? ?? ?? ?? ?? 83 d2 00 41 8b fa 3b ce 75 } 		$a_01_1 = {74 68 75 73 20 62 61 6c 20 48 69 74 20 72 69 76 65 20 43 6f 6f 6b 20 4c 69 6e } 		$a_01_2 = {5c 54 68 69 73 5c 34 39 5c 73 6f 6c 64 69 65 72 5c 48 6f 70 65 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}