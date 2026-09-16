rule Trojan_BAT_FormBook_MBXU_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {fe 04 16 fe 01 13 09 11 09 2c 2b 00 72 0f 06 00 70 } 		$a_01_1 = {72 70 67 41 73 73 69 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 		$a_01_2 = {54 00 5a 00 49 00 4e 00 4f 00 55 00 20 00 41 00 4e 00 54 00 4f 00 4e 00 49 00 41 00 } 		$a_01_3 = {33 00 49 00 2d 00 54 00 45 00 50 00 30 00 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=9
 
}