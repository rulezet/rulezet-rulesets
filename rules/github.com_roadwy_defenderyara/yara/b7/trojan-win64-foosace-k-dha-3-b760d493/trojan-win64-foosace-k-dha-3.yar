rule Trojan_Win64_Foosace_K_dha_3{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 c7 44 c8 08 10 00 00 00 8b ca 48 03 c9 ff c2 48 8d 05 ?? ?? ?? ?? 49 89 04 c8 41 c7 44 c8 08 15 00 00 00 8b ca 48 03 c9 ff c2 } 		$a_03_1 = {48 89 81 28 02 00 00 48 85 c0 0f 84 ?? 00 00 00 48 8b 0d ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 48 89 81 00 03 00 00 } 		$a_03_2 = {78 02 00 00 33 d2 44 8b c0 48 8b 05 ?? ?? ?? ?? 8d 4a 01 ff 90 90 10 02 00 00 90 09 02 00 ff 90 90 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}