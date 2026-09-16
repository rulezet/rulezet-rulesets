rule TrojanSpy_AndroidOS_SmsThief_Z_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 2f 64 77 75 72 69 61 6e 7a 73 32 33 } 		$a_01_1 = {53 65 6e 64 53 6d 73 41 63 74 69 76 69 74 79 } 		$a_01_2 = {64 75 72 69 61 6e 6b 69 6e 67 2e 6d 79 64 69 76 65 61 70 70 2e 6f 6e 6c 69 6e 65 } 		$a_01_3 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 69 70 61 79 46 50 58 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}