rule Ransom_MSIL_Cryptolocker_PDO_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 69 6f 6e 4e 6f 74 43 6f 6d 70 6c 65 74 } 		$a_81_1 = {57 72 69 74 65 46 69 6c 65 } 		$a_81_2 = {6c 6f 6b 6a 68 67 66 64 65 72 } 		$a_81_3 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } 		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}