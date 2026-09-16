rule Trojan_AndroidOS_Fakecalls_M{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 75 68 33 54 51 70 6d 4e 44 65 4f 57 5a 4d 73 49 79 39 37 2b } 		$a_01_1 = {41 50 4b 20 44 6f 77 6e 6c 6f 61 64 20 46 61 69 6c 65 64 20 64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 20 63 61 74 63 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}