rule Trojan_Win64_BumbleBee_JK_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 41 b8 00 30 00 00 8b 53 ?? 44 8d 49 ?? ff 15 } 		$a_03_1 = {8b 82 94 00 00 00 35 ?? ?? ?? ?? 2b c8 48 8d 05 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 48 89 42 ?? 89 4a } 		$a_00_2 = {56 49 44 52 56 53 74 61 74 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}