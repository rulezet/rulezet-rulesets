rule Ransom_MSIL_Cryptolocker_PDM_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 45 4c 50 5f 44 45 43 52 59 50 54 5f 59 4f 55 52 5f 46 49 4c 45 53 } 		$a_81_1 = {2e 65 6e 63 72 79 70 74 65 64 } 		$a_81_2 = {65 6e 63 72 79 70 74 46 69 6c 65 } 		$a_81_3 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}