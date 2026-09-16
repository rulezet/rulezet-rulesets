rule Trojan_Win64_Dridex_GA_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {6f 6e 75 70 6b 72 65 61 73 6f 6e 69 6e 67 43 68 72 6f 6d 65 32 52 4c 5a 63 49 6e 74 65 72 6e 65 74 32 30 30 38 2e 32 38 } 		$a_02_1 = {42 8a 1c 0a 8b 44 24 ?? 83 f0 ff 48 8b 94 24 ?? ?? ?? ?? 44 28 d3 48 29 d1 89 84 24 ?? ?? ?? ?? 42 88 9c 0c ?? ?? ?? ?? 66 8b b4 24 ?? ?? ?? ?? 66 83 f6 ff 66 89 b4 24 ?? ?? ?? ?? 4d 01 d9 } 	condition:
		((#a_81_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}