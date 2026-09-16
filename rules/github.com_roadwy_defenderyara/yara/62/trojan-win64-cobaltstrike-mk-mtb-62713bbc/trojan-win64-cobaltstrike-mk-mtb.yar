rule Trojan_Win64_CobaltStrike_MK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c9 48 8b 54 24 68 8b 84 02 00 01 00 00 2b c1 b9 [0-04] 48 6b c9 03 48 8b 54 24 68 89 84 0a 00 01 00 00 e9 } 		$a_03_1 = {33 c8 8b c1 48 8b 4c 24 68 89 41 50 48 8b 44 24 68 48 63 40 7c 48 8b 4c 24 68 48 8b 89 [0-04] 0f b6 54 24 30 88 14 01 48 8b 44 24 68 8b 40 7c ff c0 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}