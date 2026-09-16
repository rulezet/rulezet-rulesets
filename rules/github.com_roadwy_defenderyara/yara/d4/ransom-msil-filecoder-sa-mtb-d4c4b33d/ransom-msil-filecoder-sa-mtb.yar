rule Ransom_MSIL_Filecoder_SA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {21 21 21 52 65 61 64 6d 65 21 21 21 48 65 6c 70 21 21 21 2e 74 78 74 } 		$a_81_1 = {64 61 74 61 31 39 39 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 		$a_81_2 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 } 		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}