rule Ransom_MSIL_Cryptolocker_PDF_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 75 63 6b 20 52 61 74 73 20 41 6e 74 69 76 69 72 75 73 } 		$a_81_1 = {48 59 44 52 41 20 20 52 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_2 = {44 65 63 72 79 70 74 20 59 6f 75 72 20 46 69 6c 65 73 } 		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}