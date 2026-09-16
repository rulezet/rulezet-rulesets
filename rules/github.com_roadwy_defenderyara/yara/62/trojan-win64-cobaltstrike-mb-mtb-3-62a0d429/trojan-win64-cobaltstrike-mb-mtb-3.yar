rule Trojan_Win64_CobaltStrike_MB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 84 18 89 d5 c1 c5 [0-01] 89 d3 c1 c3 [0-01] c1 ea [0-01] 31 da 31 ea 8b 6c 84 [0-01] 8b 5c 84 [0-01] 89 df c1 c7 [0-01] 89 de c1 c6 [0-01] c1 eb [0-01] 31 f3 31 fb 03 6c 84 [0-01] 01 d5 01 dd 89 6c 84 [0-01] 48 83 c0 [0-01] 48 83 f8 [0-01] 75 } 		$a_01_1 = {62 72 6f 6b 65 6e 20 70 69 70 65 } 		$a_01_2 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 62 6f 72 74 65 64 } 		$a_01_3 = {6f 77 6e 65 72 20 64 65 61 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}