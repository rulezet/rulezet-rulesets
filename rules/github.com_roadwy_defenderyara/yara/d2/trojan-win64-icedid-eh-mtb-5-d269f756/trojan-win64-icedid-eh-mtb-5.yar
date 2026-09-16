rule Trojan_Win64_IcedID_EH_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 67 6a 68 73 61 68 6a 61 73 6b 73 64 } 		$a_01_1 = {64 74 32 31 6d 70 61 } 		$a_01_2 = {6b 77 62 4f 61 42 73 31 } 		$a_01_3 = {71 43 7a 67 64 39 31 68 39 } 		$a_01_4 = {75 41 66 53 62 53 6a 71 50 64 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}