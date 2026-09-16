rule Ransom_MSIL_Cryptolocker_PDD_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 75 63 63 65 73 73 20 44 65 63 72 79 70 74 } 		$a_81_1 = {42 61 64 64 79 2e 52 65 73 6f 75 72 63 65 73 } 		$a_81_2 = {2e 62 61 64 64 79 } 		$a_81_3 = {57 72 6f 6e 67 2e 48 61 68 61 68 61 2e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}