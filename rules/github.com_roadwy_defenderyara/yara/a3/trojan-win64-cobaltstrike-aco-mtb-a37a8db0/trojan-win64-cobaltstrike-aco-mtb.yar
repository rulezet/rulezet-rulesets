rule Trojan_Win64_CobaltStrike_ACO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 14 01 33 d2 8b 44 24 28 f7 74 24 54 8b c2 8b c0 48 63 4c 24 28 48 8b 54 24 58 0f b6 44 04 40 88 04 0a } 		$a_01_1 = {b8 41 00 00 00 66 89 44 24 48 b8 33 00 00 00 66 89 44 24 4a b8 43 00 00 00 66 89 44 24 4c b8 38 00 00 00 66 89 44 24 4e b8 32 00 00 00 66 89 44 24 50 b8 31 00 00 00 66 89 44 24 52 b8 37 00 00 00 66 89 44 24 54 b8 30 00 00 00 66 89 44 24 56 33 c0 66 89 44 24 58 c7 44 24 60 08 00 00 00 ff 15 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}