rule TrojanSpy_AndroidOS_SmsThief_AF_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 44 53 5f 4d 41 49 4e 5f 49 4e 54 45 52 53 54 49 54 49 41 4c 5f 49 4e 54 45 52 56 41 4c } 		$a_01_1 = {73 67 64 75 72 69 61 6e 6b 69 6e 67 2e 6d 79 64 69 76 65 61 70 70 2e 6f 6e 6c 69 6e 65 } 		$a_01_2 = {52 65 6d 6f 74 65 43 6f 6e 66 69 67 } 		$a_01_3 = {53 6d 73 53 65 6e 64 53 65 72 76 69 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}