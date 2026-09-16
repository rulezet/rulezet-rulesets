rule Trojan_Win64_IcedID_EH_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 30 51 49 71 4d 61 } 		$a_01_1 = {64 44 48 31 41 35 61 70 54 4c 41 } 		$a_01_2 = {65 30 4c 70 4a 53 38 7a 64 } 		$a_01_3 = {68 4c 6c 6c 49 67 30 4d 4b 58 } 		$a_01_4 = {69 6a 6e 69 75 61 73 68 64 79 67 75 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}