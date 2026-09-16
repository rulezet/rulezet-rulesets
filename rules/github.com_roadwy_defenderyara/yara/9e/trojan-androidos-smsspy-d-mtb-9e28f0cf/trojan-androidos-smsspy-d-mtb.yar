rule Trojan_AndroidOS_SmsSpy_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 20 6d 6f 6f 6e 5f 73 65 6e 64 5f 73 6d 73 } 		$a_00_1 = {6d 6f 6f 6e 5f 73 79 73 5f 69 6e 73 74 61 6c 6c 5f 61 70 70 20 73 74 61 72 74 20 69 6e 73 74 61 6c 6c 20 61 70 6b } 		$a_00_2 = {6d 6f 6f 6e 5f 73 79 73 5f 67 65 74 5f 75 73 65 72 69 6e 66 6f } 		$a_00_3 = {4d 4f 4e 49 54 4f 52 53 4d 53 } 		$a_00_4 = {61 6b 6e 73 65 72 76 65 72 5f 70 74 6c 2e 64 61 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}