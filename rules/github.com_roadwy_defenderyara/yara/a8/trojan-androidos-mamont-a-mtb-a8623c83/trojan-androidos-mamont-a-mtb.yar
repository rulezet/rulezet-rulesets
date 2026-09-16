rule Trojan_AndroidOS_Mamont_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Mamont.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 65 65 64 65 64 2e 70 68 70 3f 69 31 3d } 		$a_01_1 = {2f 62 61 6c 2e 70 68 70 3f 69 31 3d } 		$a_01_2 = {2f 64 72 6f 70 6e 6e 6e 61 2e 74 78 74 } 		$a_01_3 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 65 6e 64 73 6d 73 } 		$a_01_4 = {63 66 35 36 34 34 35 2e 74 77 31 2e 72 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}