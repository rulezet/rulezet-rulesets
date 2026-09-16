rule Ransom_MSIL_Cryptolocker_PDF_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 69 64 64 65 6e 2d 74 65 61 72 } 		$a_81_1 = {41 45 53 5f 45 6e 63 72 79 70 74 } 		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } 		$a_81_3 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } 		$a_81_4 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}