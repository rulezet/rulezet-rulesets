rule Ransom_MSIL_Cryptolocker_PDA_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 4c 6f 63 6b 65 72 } 		$a_81_1 = {40 57 61 6e 6e 61 50 65 61 63 65 } 		$a_81_2 = {6b 65 79 32 2e 69 63 6f } 		$a_81_3 = {42 69 74 63 6f 69 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}