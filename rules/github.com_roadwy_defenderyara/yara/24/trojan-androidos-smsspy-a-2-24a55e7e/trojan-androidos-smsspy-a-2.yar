rule Trojan_AndroidOS_SmsSpy_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 73 69 70 68 6f 6e 33 2f 73 6d 73 72 65 63 65 69 76 65 64 } 		$a_00_1 = {26 72 65 63 65 69 76 65 53 4d 53 3d 74 72 75 65 } 		$a_00_2 = {26 6c 61 73 74 73 6d 73 26 6d 65 73 73 61 67 65 3d } 		$a_00_3 = {48 69 64 65 3d 54 72 75 65 26 61 6e 64 72 6f 69 64 69 64 3d } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}