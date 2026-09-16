rule Trojan_Win64_IcedID_DM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {65 78 67 44 58 2e 64 6c 6c } 		$a_01_2 = {43 6f 46 69 6c 65 54 69 6d 65 54 6f 44 6f 73 44 61 74 65 54 69 6d 65 } 		$a_01_3 = {47 65 74 50 6f 6c 79 46 69 6c 6c 4d 6f 64 65 } 		$a_01_4 = {43 72 65 61 74 65 50 61 6c 65 74 74 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}