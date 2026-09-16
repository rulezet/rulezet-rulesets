rule Ransom_MSIL_Cryptolocker_PDC_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 46 69 6c 65 73 20 57 65 72 65 20 45 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {45 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 66 69 6c 65 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } 		$a_81_2 = {45 6e 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } 		$a_81_3 = {2e 63 72 79 70 74 73 68 69 65 6c 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}