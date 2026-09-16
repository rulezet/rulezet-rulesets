rule Trojan_AndroidOS_Fakecalls_D_2{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 65 64 2c 20 73 68 6f 77 41 63 63 65 73 73 3a } 		$a_01_1 = {45 75 68 33 54 51 70 6d 4e 44 65 4f 57 5a 4d 73 49 79 39 37 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}