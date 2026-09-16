rule Trojan_Win64_CobaltStrike_MD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 88 14 01 ff 05 ?? ?? ?? ?? 48 63 4b 7c 48 8b 83 c8 00 00 00 44 88 0c 01 ff 43 7c 8b 05 ?? ?? ?? ?? 8b 8b 94 00 00 00 05 4e 0b fb 28 03 0d ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? 49 81 fa 30 44 04 00 0f 8c } 		$a_03_1 = {33 83 98 00 00 00 83 e8 06 01 81 94 00 00 00 8b 83 a8 00 00 00 48 8b 15 ?? ?? ?? ?? 2d 05 d4 09 00 31 05 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}