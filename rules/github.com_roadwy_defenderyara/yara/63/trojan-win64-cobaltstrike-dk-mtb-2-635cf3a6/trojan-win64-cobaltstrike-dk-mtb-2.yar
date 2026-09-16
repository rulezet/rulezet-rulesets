rule Trojan_Win64_CobaltStrike_DK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 48 8d 15 ?? ?? 00 00 33 04 8a b9 04 00 00 00 48 6b c9 07 48 8b 54 24 20 33 04 0a 89 44 24 1c 48 8b 44 24 20 48 83 c0 20 48 89 44 24 20 8b 44 24 2c ff c8 89 44 24 2c 83 7c 24 2c 00 75 } 		$a_01_1 = {49 8d 04 12 41 83 c0 04 41 8b 4c 01 f8 8b 40 f8 33 0a 89 02 48 8d 52 04 41 89 4c 13 f4 44 3b 43 04 7c } 		$a_01_2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}