rule Trojan_Win64_CobaltStrike_AJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 03 c0 41 02 10 88 54 24 ?? 41 0f b6 08 0f b6 c2 48 8d 54 24 ?? 48 03 d0 0f b6 02 41 88 00 88 0a 0f b6 54 24 ?? 44 0f b6 44 24 ?? 0f b6 4c 14 ?? 42 02 4c 04 ?? 0f b6 c1 0f b6 4c 04 ?? 42 32 4c 0b 0f 41 88 49 ff 48 83 ef 01 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}