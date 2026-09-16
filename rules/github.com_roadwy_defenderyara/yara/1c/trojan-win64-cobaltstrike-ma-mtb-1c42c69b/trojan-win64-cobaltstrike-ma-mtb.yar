rule Trojan_Win64_CobaltStrike_MA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 ee ff c6 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 43 32 04 02 41 88 00 49 ff c0 3b f3 72 cb } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}