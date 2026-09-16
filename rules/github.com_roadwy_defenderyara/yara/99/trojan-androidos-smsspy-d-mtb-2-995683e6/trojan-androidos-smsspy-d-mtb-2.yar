rule Trojan_AndroidOS_SmsSpy_D_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 6e 65 74 2f 6d 61 6e 61 67 65 72 2f 43 61 6c 6c 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 3b } 		$a_00_1 = {2f 6d 6f 6e 69 74 6f 72 2f 53 6d 73 4d 6f 6e 69 74 6f 72 3b } 		$a_00_2 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 } 		$a_00_3 = {2f 41 6e 64 72 6f 69 64 2f 53 6d 61 2f 4c 6f 67 } 		$a_00_4 = {2f 6d 6f 62 69 6c 65 2f 6d 65 74 68 6f 64 34 } 		$a_00_5 = {2f 6d 6f 62 69 6c 65 2f 75 70 6c 6f 61 64 53 6d 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}