rule Ransom_MSIL_Filecoder_DA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 75 74 65 52 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_1 = {73 65 63 72 65 74 2e 74 78 74 } 		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}