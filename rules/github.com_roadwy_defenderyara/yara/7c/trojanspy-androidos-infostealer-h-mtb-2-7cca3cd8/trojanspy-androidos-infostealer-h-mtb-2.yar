rule TrojanSpy_AndroidOS_InfoStealer_H_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 73 74 2f 75 70 6c 6f 61 64 63 6f 6e 74 61 63 74 } 		$a_00_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 72 61 77 } 		$a_00_2 = {68 69 64 65 41 70 70 } 		$a_00_3 = {61 64 64 72 65 73 73 4c 69 73 74 } 		$a_00_4 = {53 4d 53 4f 62 73 65 72 76 65 72 } 		$a_00_5 = {4d 53 47 55 70 6c 6f 61 64 65 64 } 		$a_00_6 = {2f 4a 59 53 79 73 74 65 6d 2f 72 65 73 74 49 6e 74 2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 44 61 74 61 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}