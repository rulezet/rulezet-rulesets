rule Trojan_Win64_CobaltStrike_KK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff } 		$a_01_1 = {4c 6f 61 64 65 72 2e 6e 69 6d } 		$a_01_2 = {62 63 6d 6f 64 65 2e 6e 69 6d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}