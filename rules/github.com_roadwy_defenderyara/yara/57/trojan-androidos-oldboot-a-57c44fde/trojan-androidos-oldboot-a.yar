rule Trojan_AndroidOS_Oldboot_A{
	meta:
		description = "Trojan:AndroidOS/Oldboot.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 7a 79 36 2e 63 6f 6d 2c 6c 61 6e 64 66 79 2e 63 6f 6d 2c 33 36 36 6a 6f 62 73 2e 63 6f 6d 00 } 		$a_01_1 = {61 6e 64 72 6f 6c 64 39 39 39 2e 63 6f 6d 3a 38 30 39 30 2f 62 61 63 6b 75 72 6c 2e 64 6f 00 } 		$a_01_2 = {61 6e 64 72 6f 69 64 2e 67 6f 6f 67 6c 65 6b 65 72 6e 65 6c 2f 2f 64 62 2f 2f 69 74 2e 69 00 } 		$a_01_3 = {3a 38 30 39 30 2f 69 6e 73 74 61 6c 6c 61 70 70 2e 64 6f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}