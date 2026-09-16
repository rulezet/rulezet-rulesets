rule Trojan_Win64_CobaltStrike_BW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 41 8b c9 41 f7 e9 41 03 d1 41 ff c1 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b c2 07 2b c8 48 63 c1 0f b6 4c 84 20 42 30 4c 14 40 49 ff c2 4c 3b d7 7c } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}