rule Trojan_AndroidOS_SmsSpy_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {4a 61 76 61 5f 63 6f 6d 5f 73 61 6d 73 75 6e 67 5f 61 70 70 73 74 6f 72 65 36 5f 4d 61 73 6b 65 72 5f 67 65 74 4d 73 67 } 		$a_00_1 = {2f 61 70 69 5f 70 68 6f 6e 65 62 6f 6f 6b 2e 70 68 70 } 		$a_00_2 = {2f 61 70 69 5f 6d 73 67 2e 70 68 70 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}