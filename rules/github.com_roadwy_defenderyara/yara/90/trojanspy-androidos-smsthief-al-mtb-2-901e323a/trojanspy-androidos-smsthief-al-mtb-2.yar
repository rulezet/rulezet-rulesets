rule TrojanSpy_AndroidOS_SmsThief_AL_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } 		$a_01_1 = {50 4f 53 54 5f 43 4f 4e 54 41 43 54 } 		$a_01_2 = {53 4d 53 5f 55 52 49 5f 41 4c 4c } 		$a_01_3 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } 		$a_01_4 = {70 68 6f 6e 65 2f 74 72 61 6e 73 66 65 72 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}