rule Ransom_MSIL_Cryptolocker_PDE_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4b 34 4b 72 61 6e 73 6f 6d } 		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 		$a_81_2 = {46 69 6c 65 45 6e 63 72 79 70 74 } 		$a_81_3 = {45 6e 63 72 79 70 74 65 72 } 		$a_81_4 = {53 74 61 6c 69 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}