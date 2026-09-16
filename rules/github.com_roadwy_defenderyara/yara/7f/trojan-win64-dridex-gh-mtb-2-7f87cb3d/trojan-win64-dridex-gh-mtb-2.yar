rule Trojan_Win64_Dridex_GH_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 d8 41 f6 e2 88 84 24 0d 01 00 00 89 4c 24 ?? 4c 89 c1 44 8b 44 24 ?? e8 ?? ?? ?? ?? 48 8b 8c 24 d0 00 00 00 e8 } 		$a_02_1 = {4c 89 f2 44 8b 5c 24 ?? 44 89 44 24 ?? 45 89 d8 8b 6c 24 ?? 44 89 4c 24 ?? 41 89 e9 48 89 7c 24 ?? ff d0 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}