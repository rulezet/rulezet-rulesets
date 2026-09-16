rule Trojan_Win64_CobaltStrike_CC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 48 8b 49 ?? 48 c1 e9 1e 66 90 90 48 83 f9 04 73 } 		$a_01_1 = {61 6e 74 69 53 61 6e 64 62 6f 78 43 68 65 63 6b 73 } 		$a_01_2 = {65 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=8
 
}