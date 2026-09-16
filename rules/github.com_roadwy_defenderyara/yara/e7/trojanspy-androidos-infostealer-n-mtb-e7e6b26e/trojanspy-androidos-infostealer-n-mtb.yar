rule TrojanSpy_AndroidOS_InfoStealer_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6c 69 76 65 43 61 6c 6c 48 69 73 74 6f 72 79 } 		$a_00_1 = {67 65 74 54 68 69 72 64 41 70 70 4c 69 73 74 } 		$a_00_2 = {64 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 42 79 49 64 } 		$a_00_3 = {73 74 61 72 74 4c 69 76 65 52 65 63 6f 72 64 } 		$a_00_4 = {73 65 6e 64 53 4d 53 } 		$a_00_5 = {63 61 6c 6c 73 4c 69 73 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}