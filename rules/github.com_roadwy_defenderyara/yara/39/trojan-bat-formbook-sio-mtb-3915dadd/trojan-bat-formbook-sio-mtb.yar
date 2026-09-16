rule Trojan_BAT_FormBook_SIO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {3a 2f 2f 61 69 64 65 63 61 2e 6f 72 67 2e 70 65 2f 6d 6a 2f 70 61 6e 65 6c 2f 75 70 6c 6f 61 64 73 2f 47 67 70 61 6f 62 2e 64 61 74 } 		$a_81_1 = {54 6e 6f 71 66 6c 77 74 6c 73 61 2e 6a 70 65 67 } 		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}