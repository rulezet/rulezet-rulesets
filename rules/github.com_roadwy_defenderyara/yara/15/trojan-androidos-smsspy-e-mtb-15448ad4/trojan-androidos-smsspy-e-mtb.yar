rule Trojan_AndroidOS_SmsSpy_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 5f 73 6d 73 00 6d 5f 64 61 65 6d 6f 6e 73 65 72 76 69 63 65 00 6d 5f 73 6d 73 73 65 72 76 69 63 65 00 6d 5f 73 79 73 69 6e 66 6f } 		$a_00_1 = {73 6d 73 70 74 6c 76 00 76 73 5f 66 69 6c 74 65 72 2e 74 78 74 } 		$a_00_2 = {73 2f 62 31 2f 6d 61 69 6e 2f 6d 61 69 6e 2e 64 61 74 } 		$a_00_3 = {26 50 68 6f 6e 65 49 6e 66 6f 3d } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}