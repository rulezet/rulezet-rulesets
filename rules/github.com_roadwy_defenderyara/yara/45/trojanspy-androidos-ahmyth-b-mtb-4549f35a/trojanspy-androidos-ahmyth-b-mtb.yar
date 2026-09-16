rule TrojanSpy_AndroidOS_Ahmyth_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 57 68 61 74 73 41 70 70 2f 4d 65 64 69 61 2f 57 68 61 74 73 41 70 70 20 44 6f 63 75 6d 65 6e 74 73 2f } 		$a_00_1 = {2f 2e 53 79 73 74 65 6d 2f 52 65 63 6f 72 64 73 2f } 		$a_00_2 = {2f 73 79 73 74 65 6d 2e 61 70 6b } 		$a_00_3 = {73 74 61 72 74 52 65 63 6f 72 64 69 6e 67 } 		$a_00_4 = {73 6d 73 4c 69 73 74 } 		$a_00_5 = {2f 73 65 72 76 65 72 2f 75 70 6c 6f 61 64 2e 70 68 70 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}