rule Ransom_MSIL_FileCoder_MVT_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {46 65 6e 72 69 6b 77 61 72 65 } 		$a_80_1 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_80_2 = {53 68 61 64 6f 77 43 6f 70 79 } 		$a_00_3 = {46 69 6c 75 6d 45 6e 63 72 79 70 74 6f } 	condition:
		((#a_00_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}