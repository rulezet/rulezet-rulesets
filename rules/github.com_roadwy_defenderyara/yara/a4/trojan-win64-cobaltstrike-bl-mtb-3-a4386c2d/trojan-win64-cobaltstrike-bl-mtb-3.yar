rule Trojan_Win64_CobaltStrike_BL_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 39 c3 7e ?? 48 89 c2 83 e2 ?? 8a 14 17 32 14 06 88 14 01 48 ff c0 eb } 		$a_03_1 = {41 89 d0 42 80 3c 01 ?? 74 ?? 41 89 c1 46 0f b7 04 01 ff c2 41 c1 c9 ?? 45 01 c8 44 31 c0 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}