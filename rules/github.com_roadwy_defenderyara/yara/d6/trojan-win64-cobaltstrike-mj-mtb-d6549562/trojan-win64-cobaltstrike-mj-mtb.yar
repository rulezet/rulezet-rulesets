rule Trojan_Win64_CobaltStrike_MJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af d0 48 8b 83 c8 00 00 00 88 14 01 44 8b 83 b4 00 00 00 8b 4b 54 44 8b 8b e0 00 00 00 8b ab d8 00 00 00 8b c5 ff 83 88 00 00 00 41 8d ?? ?? ?? ?? ?? 8b 73 58 41 33 c0 } 		$a_03_1 = {89 43 54 89 0b 8d 82 ?? ?? ?? ?? 41 03 c1 01 43 08 44 8b 73 08 49 81 fb } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}