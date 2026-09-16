rule Trojan_AndroidOS_Fakeapp_M_2{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 73 20 6e 6f 74 20 61 20 64 61 6e 67 65 72 6f 75 73 20 70 65 72 6d 69 73 73 69 6f 6e 20 6f 72 20 73 70 65 63 69 61 6c 20 70 65 72 6d 69 73 73 69 6f 6e } 		$a_01_1 = {73 79 73 74 65 6d 50 68 6f 74 6f 4c 69 73 74 73 } 		$a_01_2 = {77 72 65 73 75 6c 74 4d 61 70 64 61 64 61 } 		$a_01_3 = {74 68 65 20 61 6e 72 20 70 72 6f 63 65 73 73 20 66 6f 75 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}