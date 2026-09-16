rule Ransom_MSIL_Cryptolocker_PDQ_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {49 27 6d 20 72 75 6e 6e 69 6e 67 20 69 6e 20 44 65 62 75 67 20 6d 6f 64 65 } 		$a_81_1 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } 		$a_81_2 = {4a 69 67 73 61 77 52 61 6e 73 6f 6d 77 61 72 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}