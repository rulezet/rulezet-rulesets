rule Trojan_AndroidOS_SmsSpy_A{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 61 70 70 5f 6e 61 6d 65 3d } 		$a_00_1 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 3d } 		$a_01_2 = {2f 73 6f 75 6e 64 2f 53 6f 75 6e 64 53 65 72 76 69 63 65 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}