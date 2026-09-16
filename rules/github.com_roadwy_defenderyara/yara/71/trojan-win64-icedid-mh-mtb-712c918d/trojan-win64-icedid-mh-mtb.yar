rule Trojan_Win64_IcedID_MH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 6c 6d 71 32 35 37 71 74 38 2e 64 6c 6c } 		$a_01_1 = {42 79 55 65 64 37 34 31 62 } 		$a_01_2 = {44 54 65 54 36 30 33 72 4b 52 } 		$a_01_3 = {4e 66 75 34 34 65 } 		$a_01_4 = {54 49 4a 6c 4f 36 31 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}