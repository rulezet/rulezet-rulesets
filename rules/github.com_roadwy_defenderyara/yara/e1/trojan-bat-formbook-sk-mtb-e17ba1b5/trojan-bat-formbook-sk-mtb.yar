rule Trojan_BAT_FormBook_SK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 70 61 64 46 6f 72 6d 53 61 6d 70 6c 65 72 } 		$a_81_1 = {44 65 70 65 6e 64 65 6e 63 79 50 72 6f 70 65 72 74 79 57 65 61 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_2 = {24 45 34 42 37 41 33 46 39 2d 36 43 32 44 2d 34 41 38 45 2d 39 46 35 42 2d 31 44 38 41 34 43 37 45 32 42 36 46 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}