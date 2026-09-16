rule TrojanSpy_AndroidOS_SmsThief_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 72 65 61 6c 73 70 79 2f } 		$a_00_1 = {2f 72 65 61 6c 72 61 74 2f } 		$a_00_2 = {73 6d 73 74 6f 63 6f 6e 74 61 63 74 73 } 		$a_00_3 = {68 69 64 65 61 70 6b } 		$a_00_4 = {63 6f 6e 74 61 63 74 73 2e 74 78 74 } 		$a_00_5 = {53 4d 53 49 6e 74 65 72 63 65 70 74 6f 72 } 		$a_00_6 = {70 6f 73 74 5f 64 61 74 61 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}