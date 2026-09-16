rule Trojan_Win64_IcedID_EH_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 48 6e 67 44 6e 36 70 } 		$a_01_1 = {41 50 34 68 4e 73 52 6b 69 75 7a } 		$a_01_2 = {47 51 30 69 4f 6d 49 } 		$a_01_3 = {4f 52 35 6e 5a 77 } 		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}