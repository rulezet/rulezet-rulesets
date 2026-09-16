rule Trojan_AndroidOS_Oldboot_A_2{
	meta:
		description = "Trojan:AndroidOS/Oldboot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3f 63 61 72 64 69 64 3d 00 } 		$a_01_1 = {26 61 70 70 69 64 3d 00 0b 26 63 68 61 6e 6e 65 6c 69 64 3d 00 05 26 6e 65 74 3d 00 } 		$a_01_2 = {31 30 2e 30 2e 30 2e 31 37 32 00 0a 31 30 2e 30 2e 30 2e 32 30 30 00 } 		$a_01_3 = {73 65 72 76 69 63 65 2f 42 6f 6f 74 52 65 63 76 3b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}