rule Trojan_Win64_CobaltStrike_MO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 6c 24 78 48 8d 6c 24 78 48 89 84 24 88 00 00 00 4c 89 84 24 b0 00 00 00 48 89 bc 24 a0 00 00 00 48 89 b4 24 a8 00 00 00 e8 ?? ?? ?? ?? 0f 1f 00 48 85 c9 0f 85 04 01 00 00 ?? b9 0c 00 00 00 bf 10 00 00 00 } 		$a_01_1 = {56 76 5a 64 78 38 6b 79 44 78 38 77 43 5a 65 57 52 62 73 4b } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}