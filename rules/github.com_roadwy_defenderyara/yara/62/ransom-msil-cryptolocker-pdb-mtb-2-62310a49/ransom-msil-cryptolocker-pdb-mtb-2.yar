rule Ransom_MSIL_Cryptolocker_PDB_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 61 76 65 20 66 75 6e 20 65 78 70 6c 6f 72 69 6e 67 20 79 6f 75 72 20 63 6f 72 72 75 70 74 65 64 20 66 69 6c 65 73 } 		$a_81_1 = {4b 65 79 20 69 73 20 64 65 73 74 72 6f 79 65 64 } 		$a_81_2 = {44 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 } 		$a_81_3 = {43 72 61 70 73 6f 6d 77 61 72 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}