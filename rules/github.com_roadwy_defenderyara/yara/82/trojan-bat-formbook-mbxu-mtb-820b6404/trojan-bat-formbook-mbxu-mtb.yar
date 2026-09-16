rule Trojan_BAT_FormBook_MBXU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 2d 32 63 62 34 30 39 34 39 64 37 32 65 } 		$a_01_1 = {72 65 64 69 73 74 2e 65 78 65 } 		$a_01_2 = {52 65 64 69 73 74 2e 42 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67 } 		$a_01_3 = {24 35 37 34 63 38 63 62 37 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=12
 
}