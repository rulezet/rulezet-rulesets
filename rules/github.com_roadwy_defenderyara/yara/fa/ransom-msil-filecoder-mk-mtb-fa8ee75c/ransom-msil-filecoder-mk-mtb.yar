rule Ransom_MSIL_Filecoder_MK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_1 = {63 6f 6d 70 6f 6e 65 6e 74 2f 61 70 70 2e 78 61 6d 6c } 		$a_81_2 = {48 61 63 6b 65 61 64 6f 20 50 75 74 61 } 		$a_81_3 = {43 79 70 74 65 64 52 65 61 64 79 2e 69 6e 69 } 		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_5 = {63 6f 6d 70 6f 6e 65 6e 74 2f 6d 61 69 6e 77 69 6e 64 6f 77 2e 78 61 6d 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}