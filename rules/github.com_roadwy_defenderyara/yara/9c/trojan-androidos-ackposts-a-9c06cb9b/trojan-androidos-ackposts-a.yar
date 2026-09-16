rule Trojan_AndroidOS_Ackposts_A{
	meta:
		description = "Trojan:AndroidOS/Ackposts.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 51 75 65 72 79 4d 69 73 73 4f 72 64 65 72 43 61 6c 6c 62 61 63 6b } 		$a_01_1 = {76 33 66 6d 68 72 70 31 35 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}