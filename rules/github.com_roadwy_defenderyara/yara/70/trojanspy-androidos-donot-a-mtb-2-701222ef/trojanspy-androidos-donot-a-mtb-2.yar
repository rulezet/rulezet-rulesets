rule TrojanSpy_AndroidOS_DoNot_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/DoNot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 53 6d 73 5f 64 74 } 		$a_00_1 = {4b 65 79 6c 6f 67 73 } 		$a_00_2 = {73 72 5f 74 6d 5f 64 75 72 } 		$a_00_3 = {6c 69 76 65 5f 72 65 63 31 5f 64 74 74 6d } 		$a_00_4 = {77 74 73 70 5f 72 65 63 } 		$a_00_5 = {77 61 5f 64 61 74 65 5f 69 64 } 		$a_00_6 = {4b 59 4c 4b 30 30 2e 74 78 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}