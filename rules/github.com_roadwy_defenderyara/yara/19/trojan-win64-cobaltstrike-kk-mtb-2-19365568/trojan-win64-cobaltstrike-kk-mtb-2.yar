rule Trojan_Win64_CobaltStrike_KK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 38 2b c2 48 63 c8 48 8d 05 b4 20 02 00 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 c4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}