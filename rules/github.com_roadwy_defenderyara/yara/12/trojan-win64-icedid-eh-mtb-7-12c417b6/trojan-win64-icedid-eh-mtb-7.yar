rule Trojan_Win64_IcedID_EH_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 47 62 46 6d 73 44 75 6c } 		$a_01_1 = {59 47 32 73 4a 75 51 75 59 56 } 		$a_01_2 = {59 4f 4e 42 7a 64 34 6b 31 48 } 		$a_01_3 = {62 54 76 6a 5a 66 59 4e 53 36 50 } 		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}