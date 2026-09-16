rule Trojan_BAT_FormBook_AF_MTB_22{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 00 11 05 7b 15 00 00 04 28 ?? ?? ?? 0a 25 26 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 00 de 05 } 		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 6f 63 75 6d 65 6e 74 73 5c 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 48 56 70 4f 4c 2e 70 64 62 } 		$a_01_2 = {48 00 56 00 70 00 4f 00 4c 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}