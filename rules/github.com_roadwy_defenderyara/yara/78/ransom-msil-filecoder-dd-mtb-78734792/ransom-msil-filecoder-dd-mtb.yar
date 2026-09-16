rule Ransom_MSIL_Filecoder_DD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } 		$a_81_1 = {75 73 65 72 50 72 69 76 61 74 65 49 64 4b 65 79 2e 74 78 74 } 		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_81_3 = {42 69 74 63 6f 69 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}