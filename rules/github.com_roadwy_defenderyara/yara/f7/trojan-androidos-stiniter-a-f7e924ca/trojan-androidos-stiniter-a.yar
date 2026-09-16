rule Trojan_AndroidOS_Stiniter_A{
	meta:
		description = "Trojan:AndroidOS/Stiniter.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 20 4d 79 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 20 6f 6e 52 65 63 65 69 76 65 20 2d 2d 2d } 		$a_01_1 = {41 6e 64 6f 69 64 53 65 72 76 69 63 65 2e 6a 61 76 61 } 		$a_01_2 = {25 54 68 72 65 61 64 2d 2d 2d 2d 2d 2d 2d 72 75 6e 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 62 72 65 61 6b 2d 2d 2d 2d 2d 2d } 		$a_01_3 = {53 74 61 72 74 20 41 6e 64 6f 69 64 53 65 72 76 69 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}