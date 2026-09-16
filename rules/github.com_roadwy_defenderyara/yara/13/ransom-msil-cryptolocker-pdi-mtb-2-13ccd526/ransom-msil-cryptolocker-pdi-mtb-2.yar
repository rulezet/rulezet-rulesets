rule Ransom_MSIL_Cryptolocker_PDI_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 64 6f 77 73 20 53 74 6f 72 65 20 44 6f 77 6e 6c 6f 61 64 } 		$a_81_1 = {2e 6c 6f 63 6b 65 64 } 		$a_81_2 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } 		$a_81_3 = {46 69 6c 65 45 78 74 65 6e 73 69 6f 6e } 		$a_81_4 = {45 6e 63 72 79 70 74 41 45 53 } 		$a_81_5 = {45 6e 63 72 79 70 74 4b 65 79 } 		$a_81_6 = {52 53 41 4b 65 79 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}