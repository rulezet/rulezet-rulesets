rule Trojan_AndroidOS_Stiniter_A_2{
	meta:
		description = "Trojan:AndroidOS/Stiniter.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 2d 20 6f 6e 43 72 65 61 74 65 20 47 6f 6f 67 6c 65 55 70 64 61 74 65 53 65 72 76 69 63 65 20 2d 2d 2d } 		$a_01_1 = {2d 2d 2d 73 74 61 72 74 20 72 6f 6f 74 53 61 74 61 65 } 		$a_01_2 = {2d 2d 2d 20 65 72 72 6f 72 20 2d 2d 2d } 		$a_01_3 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 6b 65 65 70 65 72 } 		$a_01_4 = {47 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 2e 6a 61 76 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}