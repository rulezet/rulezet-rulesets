rule Trojan_Win64_CobaltStrike_BM_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 0c 2b 09 c1 0f c9 41 33 08 0f c9 43 89 4c 32 0c 31 c0 48 8b 94 24 80 00 00 00 48 8b 6c 24 70 48 83 f8 10 74 ?? 8a 0c 02 30 4c 05 00 48 ff c0 eb } 		$a_01_1 = {34 42 65 6a 7a 38 74 78 51 2f 72 44 6e 66 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}