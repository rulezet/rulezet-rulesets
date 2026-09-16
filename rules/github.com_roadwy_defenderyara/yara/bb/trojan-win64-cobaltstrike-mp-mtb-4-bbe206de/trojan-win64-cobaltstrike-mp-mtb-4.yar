rule Trojan_Win64_CobaltStrike_MP_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 2c 41 8b c0 2b c2 48 63 c8 42 0f b6 94 11 d8 e8 00 00 43 32 94 11 d0 53 0a 00 48 8b 44 24 30 41 88 14 01 41 ff c0 49 ff c1 49 63 c0 48 3b 44 24 38 72 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}