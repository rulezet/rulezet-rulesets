rule TrojanSpy_AndroidOS_SmsThief_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 69 6e 67 20 74 65 78 74 53 6d 73 20 74 6f 20 62 65 20 73 65 6e 64 20 21 } 		$a_00_1 = {77 65 62 2e 6d 65 2e 63 6f 6d } 		$a_00_2 = {53 65 6e 64 20 43 61 6c 6c 73 20 6c 6f 67 } 		$a_00_3 = {63 68 65 63 6b 45 6d 61 69 6c 53 6d 73 } 		$a_00_4 = {50 68 6f 6e 65 4c 6f 63 61 74 6f 72 2f 50 72 6f 5f 76 65 72 73 69 6f 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}