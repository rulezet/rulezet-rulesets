rule Ransom_MSIL_Cryptolocker_PDF_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_2 = {41 52 54 45 4d 4f 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}