rule TrojanSpy_AndroidOS_Banker_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 42 67 53 65 72 76 69 63 65 3b } 		$a_00_1 = {53 6d 73 4c 69 73 74 65 6e 65 72 } 		$a_00_2 = {68 61 6e 64 6c 65 49 6e 63 6f 6d 69 6e 67 53 4d 53 } 		$a_00_3 = {63 61 6c 6c 74 72 61 6e 73 66 65 72 72 65 64 6c 69 73 74 } 		$a_00_4 = {63 61 6c 6c 63 6f 6e 74 61 63 74 73 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}