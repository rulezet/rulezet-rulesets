rule Trojan_Win64_Foosace_K_dha_2{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 57 00 52 65 67 69 73 74 65 72 4e 65 77 43 6f 6d 6d 61 6e 64 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } 		$a_03_1 = {41 b8 06 00 00 00 41 f7 f0 8b c2 8b c0 48 8b 54 24 ?? 0f b6 04 02 33 c8 } 		$a_03_2 = {b8 f4 ee ee ee eb 14 44 8b 44 24 ?? 48 8b 54 24 ?? 48 8b 4c 24 ?? e8 ?? ?? ?? ?? 48 83 c4 38 c3 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}