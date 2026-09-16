rule Trojan_BAT_Balamid_A_3{
	meta:
		description = "Trojan:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 36 34 2e 63 6f 6d 2f 75 72 6c 2e 74 78 74 } 		$a_80_1 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 } 		$a_80_2 = {22 75 72 6c 73 5f 74 6f 5f 72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 22 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}