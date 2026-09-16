rule Trojan_Win64_CobaltStrike_BV_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 e1 ff 0f 00 00 49 8b c0 48 c1 e8 [0-04] 66 29 04 11 0f b7 0f 48 8b c3 81 e1 ff 0f 00 00 48 c1 e8 [0-04] 66 01 04 11 eb [0-04] 66 83 f8 02 75 [0-04] 81 e1 ff 0f 00 00 66 44 29 04 11 0f b7 07 25 ff 0f 00 00 66 01 1c 10 48 83 c7 02 85 f6 } 		$a_03_1 = {8b 32 8b 7a ?? 8b 4a ?? 49 03 ?? 49 03 ?? 41 ff ?? f3 a4 0f b7 45 ?? 48 83 c2 28 44 3b ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}