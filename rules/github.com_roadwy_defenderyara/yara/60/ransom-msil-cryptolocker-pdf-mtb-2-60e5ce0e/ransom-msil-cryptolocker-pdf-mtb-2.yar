rule Ransom_MSIL_Cryptolocker_PDF_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 6f 6e 6f 74 20 63 72 79 } 		$a_81_1 = {2e 63 72 69 6e 67 } 		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } 		$a_81_3 = {43 72 79 46 69 6c 65 } 		$a_81_4 = {64 65 52 65 61 64 4d 65 21 21 21 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}