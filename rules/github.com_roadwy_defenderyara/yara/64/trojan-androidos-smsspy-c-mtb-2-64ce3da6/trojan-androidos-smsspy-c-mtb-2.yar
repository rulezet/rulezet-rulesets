rule Trojan_AndroidOS_SmsSpy_C_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 61 6d 73 75 6e 67 2f 61 70 70 73 74 6f 72 65 36 2f 50 47 5f 53 4d 53 4f 62 73 65 72 76 65 72 3b } 		$a_00_1 = {43 46 5f 50 65 72 73 6f 6e 44 61 74 61 2e 6a 61 76 61 } 		$a_00_2 = {6d 61 32 73 6b 65 72 } 		$a_00_3 = {67 65 74 55 70 6c 6f 61 64 50 68 6f 6e 65 62 6f 6f 6b 58 4d 4c } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}