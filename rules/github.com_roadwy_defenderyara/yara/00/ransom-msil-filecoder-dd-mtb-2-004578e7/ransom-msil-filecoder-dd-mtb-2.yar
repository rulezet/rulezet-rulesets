rule Ransom_MSIL_Filecoder_DD_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {55 6e 6c 75 63 6b 79 57 61 72 65 2e 65 78 65 } 		$a_81_1 = {42 79 74 65 6c 6f 63 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_81_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 4c 69 73 74 } 		$a_81_3 = {56 57 35 73 64 57 4e 72 65 56 64 68 63 6d 55 6b } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}