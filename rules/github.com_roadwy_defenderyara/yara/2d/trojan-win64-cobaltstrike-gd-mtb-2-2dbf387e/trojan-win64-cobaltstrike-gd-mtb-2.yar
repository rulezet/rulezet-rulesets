rule Trojan_Win64_CobaltStrike_GD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 } 		$a_01_1 = {45 8a 14 11 } 		$a_01_2 = {44 30 14 0f } 		$a_02_3 = {48 89 c8 48 81 f9 [0-04] 76 } 		$a_01_4 = {6f 6e 5f 61 76 61 73 74 5f 64 6c 6c 5f 75 6e 6c 6f 61 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}