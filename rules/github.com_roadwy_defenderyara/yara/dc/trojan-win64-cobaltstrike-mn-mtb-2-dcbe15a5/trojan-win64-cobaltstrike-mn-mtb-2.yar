rule Trojan_Win64_CobaltStrike_MN_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 48 8b 84 24 [0-04] 44 0f b6 04 08 48 63 84 24 [0-04] 33 d2 b9 ?? ?? ?? ?? 48 f7 f1 0f b6 44 14 70 41 8b d0 33 d0 } 		$a_03_1 = {03 c1 2b 44 24 58 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 2b 84 24 [0-04] 48 63 c8 48 8b 84 24 [0-04] 88 14 08 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}