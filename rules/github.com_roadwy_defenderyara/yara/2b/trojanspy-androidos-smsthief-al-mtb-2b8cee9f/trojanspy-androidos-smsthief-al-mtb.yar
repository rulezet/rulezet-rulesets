rule TrojanSpy_AndroidOS_SmsThief_AL_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 4f 42 53 65 72 76 65 72 } 		$a_01_1 = {73 6e 65 64 43 6f 6e 74 61 63 74 73 } 		$a_01_2 = {42 61 64 53 4d 53 52 65 63 65 69 76 65 72 } 		$a_01_3 = {42 41 4e 4b 5f 54 4f 50 5f 43 48 45 43 4b 5f 54 49 4d 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}