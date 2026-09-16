rule Ransom_AndroidOS_Filecoder_MTB{
	meta:
		description = "Ransom:AndroidOS/Filecoder!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 73 73 70 62 61 68 6b 2e 73 6f } 		$a_00_1 = {51 51 71 75 6e 20 35 37 31 30 31 32 37 30 36 20 } 		$a_00_2 = {54 69 6d 65 20 68 61 73 20 63 6f 6d 65 21 } 		$a_00_3 = {44 65 63 72 79 70 74 20 63 6f 6d 70 6c 65 74 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}