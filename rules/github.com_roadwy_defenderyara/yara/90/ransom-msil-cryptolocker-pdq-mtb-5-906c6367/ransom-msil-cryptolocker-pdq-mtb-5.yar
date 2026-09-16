rule Ransom_MSIL_Cryptolocker_PDQ_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {2e 48 41 4e 54 41 } 		$a_81_2 = {42 54 43 20 77 61 6c 6c 65 74 3a } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}