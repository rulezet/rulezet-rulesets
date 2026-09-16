rule Trojan_Win64_IcedID_SMG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 ?? 8b 4c 24 48 66 3b c9 } 		$a_03_1 = {0f b6 44 01 ?? 8b 4c 24 ?? 33 c8 66 3b } 		$a_03_2 = {8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? e9 } 		$a_00_3 = {88 04 0a e9 } 		$a_00_4 = {69 6e 69 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}