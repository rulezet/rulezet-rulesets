rule Trojan_Win64_Convagent_KK_MTB{
	meta:
		description = "Trojan:Win64/Convagent.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 48 8b 4c 24 40 0f b6 04 01 89 44 24 28 8b 44 24 20 99 f7 7c 24 24 8b c2 48 98 48 8b 4c 24 50 0f b6 04 01 8b 4c 24 28 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 48 88 04 0a 8b 44 24 20 ff c0 89 44 24 20 } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}