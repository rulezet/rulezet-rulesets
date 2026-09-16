rule Ransom_MSIL_Cryptolocker_PDA_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 41 72 65 20 44 65 63 72 79 70 74 65 64 } 		$a_81_1 = {46 75 63 6b 74 68 65 53 79 73 74 65 6d } 		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } 		$a_81_3 = {57 72 6f 6e 67 20 4b 65 79 20 42 69 74 63 68 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}