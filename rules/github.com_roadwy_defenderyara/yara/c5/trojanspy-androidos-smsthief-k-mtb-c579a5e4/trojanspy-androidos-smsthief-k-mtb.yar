rule TrojanSpy_AndroidOS_SmsThief_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 61 6c 72 61 74 2f } 		$a_00_1 = {5f 66 75 63 6b } 		$a_00_2 = {5f 75 70 6c 6f 61 64 73 75 63 65 73 73 } 		$a_00_3 = {50 68 6f 6e 65 53 6d 73 } 		$a_00_4 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } 		$a_00_5 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}