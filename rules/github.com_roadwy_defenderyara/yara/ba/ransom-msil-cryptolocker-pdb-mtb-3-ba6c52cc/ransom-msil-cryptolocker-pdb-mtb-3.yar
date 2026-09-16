rule Ransom_MSIL_Cryptolocker_PDB_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {58 31 4a 6c 59 32 39 32 5a 58 4a 66 53 57 35 7a 64 48 4a 31 59 33 52 70 62 32 35 7a 4c 6e 52 34 64 41 } 		$a_81_1 = {58 31 4a 6c 59 32 39 32 5a 58 4a 66 53 57 35 7a 64 48 4a 31 59 33 52 70 62 32 35 7a 4c 6e 42 75 5a 77 } 		$a_81_2 = {53 57 35 6d 61 57 35 70 64 48 6c 4d 62 32 4e 72 } 		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}