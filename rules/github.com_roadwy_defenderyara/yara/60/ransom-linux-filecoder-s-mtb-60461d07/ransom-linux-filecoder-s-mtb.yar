rule Ransom_Linux_Filecoder_S_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.S!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } 		$a_01_1 = {6d 61 69 6e 2e 47 65 74 48 6f 6d 65 44 69 72 } 		$a_00_2 = {72 65 61 64 4d 65 } 		$a_01_3 = {2f 72 6f 6f 74 2f 63 72 79 2f 65 6e 63 72 79 70 74 2e 67 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}