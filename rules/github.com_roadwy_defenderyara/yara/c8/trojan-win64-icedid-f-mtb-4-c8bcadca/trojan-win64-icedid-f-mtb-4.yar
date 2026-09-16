rule Trojan_Win64_IcedID_F_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 40 01 88 44 24 21 3a ff 74 } 		$a_03_1 = {48 03 c8 48 8b c1 66 3b ?? 74 } 		$a_03_2 = {48 8b 44 24 40 48 8b 4c 24 48 66 3b ?? 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}