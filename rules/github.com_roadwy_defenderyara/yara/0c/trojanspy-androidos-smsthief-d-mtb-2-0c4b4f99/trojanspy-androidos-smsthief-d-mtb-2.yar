rule TrojanSpy_AndroidOS_SmsThief_D_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 48 52 30 63 44 6f 76 4c 32 46 77 61 58 4e 6c 63 6e 5a 6c 63 69 35 36 65 6d 5a 35 63 43 35 6a 62 32 30 36 4d 6a 41 35 4e 53 39 68 63 47 6b 3d } 		$a_00_1 = {4c 63 6f 6d 2f 6b 62 35 33 34 2f 65 6b 73 74 76 6e 2f 6e 65 74 2f 65 6e 74 69 74 79 2f 43 61 6c 6c 4c 6f 67 45 6e 74 69 74 79 3b } 		$a_00_2 = {3f 74 79 70 65 3d 69 6e 63 6f 6d 69 6e 67 4f 6e 43 61 6c 6c } 		$a_00_3 = {2f 41 6e 64 72 6f 69 64 2f 53 6d 61 2f 4c 6f 67 } 		$a_00_4 = {67 65 74 53 6d 73 54 79 70 65 } 		$a_00_5 = {67 65 74 53 61 6c 65 72 5f 63 6f 64 65 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}