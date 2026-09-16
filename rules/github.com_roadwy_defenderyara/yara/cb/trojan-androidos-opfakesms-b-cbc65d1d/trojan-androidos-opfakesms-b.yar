rule Trojan_AndroidOS_OpFakeSms_B{
	meta:
		description = "Trojan:AndroidOS/OpFakeSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 45 51 55 45 53 54 5f 53 55 43 43 45 53 } 		$a_01_1 = {66 69 72 73 74 5f 61 63 74 69 76 69 74 79 } 		$a_01_2 = {73 75 63 63 65 73 2e 74 78 74 } 		$a_01_3 = {53 75 63 63 65 73 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } 		$a_01_4 = {69 73 4e 65 65 64 53 65 6e 64 53 6d 73 4d 65 73 73 61 67 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}