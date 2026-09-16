rule Trojan_Win64_CobaltStrike_CF_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0c ae 48 01 f9 41 0f b7 44 6d ?? 41 8b 34 84 e8 ?? ?? ?? ?? 48 01 fe 39 44 24 ?? 48 0f 44 de 48 ff c5 eb } 		$a_03_1 = {0f be 11 85 d2 74 ?? 31 d0 69 d0 ?? ?? ?? ?? 89 d0 c1 e8 ?? 31 d0 48 ff c1 eb } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}