rule Ransom_Win64_NekarkCrypt_PA_MTB_2{
	meta:
		description = "Ransom:Win64/NekarkCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 20 42 54 43 } 		$a_01_1 = {2e 63 72 6f 77 64 73 74 72 69 6b 65 } 		$a_01_2 = {5c 48 69 43 72 6f 77 64 53 74 72 69 6b 65 2e 74 78 74 } 		$a_01_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}