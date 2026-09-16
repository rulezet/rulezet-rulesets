rule Ransom_MSIL_Cryptolocker_PDC_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } 		$a_81_1 = {5f 45 6e 63 72 79 70 74 65 64 24 } 		$a_81_2 = {52 58 68 6a 61 58 52 6c 55 6b 46 4f 4a 41 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}