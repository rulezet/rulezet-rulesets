rule TrojanSpy_AndroidOS_SmsThief_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 69 72 2f 73 69 71 65 2f 68 6f 6c 6f 2f 63 6f 6e 6e 65 63 74 3b } 		$a_00_1 = {4c 69 72 2f 73 69 71 65 2f 68 6f 6c 6f 2f 4d 79 52 65 63 65 69 76 65 72 3b } 		$a_00_2 = {2e 70 68 70 3f 70 68 6f 6e 65 3d } 		$a_00_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}