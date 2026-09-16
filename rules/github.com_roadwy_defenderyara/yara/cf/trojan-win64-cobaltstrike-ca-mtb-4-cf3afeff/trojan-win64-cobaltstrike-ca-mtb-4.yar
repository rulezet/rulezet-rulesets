rule Trojan_Win64_CobaltStrike_CA_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 89 88 88 88 41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 0f 41 8b c9 2b c8 41 8d 04 4a 41 03 c0 48 63 c8 0f b6 14 31 41 32 14 24 43 8d 04 18 48 63 c8 88 14 19 41 ff c0 4d 8d 64 24 01 8b 4d af 03 cf 44 3b c1 72 } 		$a_01_1 = {31 76 35 33 64 50 32 76 34 40 66 5a 49 3f 53 65 78 76 4c 55 35 4b 7a 37 4e 29 74 3e 67 } 		$a_01_2 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } 	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}