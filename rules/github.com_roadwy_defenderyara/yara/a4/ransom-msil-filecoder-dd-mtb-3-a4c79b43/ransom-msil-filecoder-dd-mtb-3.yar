rule Ransom_MSIL_Filecoder_DD_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {40 52 45 41 44 5f 4d 45 40 2e 74 78 74 } 		$a_81_1 = {48 65 6c 6c 6f 20 2c 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 67 65 74 20 65 6e 63 72 79 70 74 65 64 20 21 } 		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } 		$a_81_3 = {77 61 6c 2e 62 6d 70 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}