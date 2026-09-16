rule Trojan_Win64_CobaltStrike_AMMF_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 ab aa aa 2a 4d 8d 52 01 41 f7 e8 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 02 2b c1 48 98 42 0f b6 04 18 41 30 42 ff 45 3b c1 7c } 		$a_01_1 = {30 14 0b 02 14 0b e2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}