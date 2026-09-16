rule Trojan_AndroidOS_SmsSpy_F_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 43 61 6d 65 72 61 2f 3f 65 3d 31 33 35 31 38 35 35 38 36 39 26 70 61 79 3d 70 61 73 61 72 67 61 64 } 		$a_00_1 = {3a 2f 2f 75 61 69 6f 65 79 2e 67 61 2f 4d 61 69 6e 44 6f 6d 61 69 6e 2e 74 78 74 } 		$a_00_2 = {64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } 		$a_00_3 = {3a 2f 2f 75 61 69 6f 65 79 2e 67 61 2f 6f 74 70 2e 70 68 70 } 		$a_00_4 = {69 72 2e 70 61 72 64 61 6b 68 74 2e 53 6d 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}