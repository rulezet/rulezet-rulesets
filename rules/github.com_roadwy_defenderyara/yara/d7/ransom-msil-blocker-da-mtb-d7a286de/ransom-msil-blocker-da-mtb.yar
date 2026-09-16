rule Ransom_MSIL_Blocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 6c 61 63 6b 20 48 61 74 20 57 6f 72 6d } 		$a_81_1 = {57 30 30 6f 72 6d 53 50 2e 65 78 65 } 		$a_81_2 = {64 64 6f 73 73 74 6f 70 } 		$a_81_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } 		$a_81_4 = {62 6c 61 63 6b 20 68 61 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}