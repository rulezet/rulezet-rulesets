rule Trojan_Win64_IcedId_JJ_MTB{
	meta:
		description = "Trojan:Win64/IcedId.JJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 f7 b4 24 ?? ?? ?? ?? eb } 		$a_03_1 = {48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 eb } 		$a_00_2 = {8b 4c 24 04 33 c8 eb } 		$a_00_3 = {8b c1 48 63 0c 24 eb } 		$a_03_4 = {48 8b 94 24 ?? ?? ?? ?? 88 04 0a e9 } 		$a_00_5 = {8b 04 24 ff c0 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}