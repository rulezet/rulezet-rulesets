rule TrojanSpy_AndroidOS_SmsThief_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 5f 73 6d 73 2e 70 68 70 } 		$a_00_1 = {65 78 74 72 61 63 74 4d 65 73 73 61 67 65 73 } 		$a_01_2 = {52 45 51 55 45 53 54 5f 43 4f 44 45 5f 53 4d 53 5f 50 45 52 4d 49 53 53 49 4f 4e } 		$a_00_3 = {62 72 2f 63 6f 6d 2f 68 65 6c 70 64 65 76 2f 6b 79 63 66 6f 72 6d 2f 72 65 63 65 69 76 65 72 2f 53 4d 53 52 65 63 65 69 76 65 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*3) >=5
 
}