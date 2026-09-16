rule Ransom_MSIL_FileCrypter_MK_MTB{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 42 6c 6f 78 2e 65 78 65 } 		$a_80_1 = {52 61 6e 73 6f 6d 42 6c 6f 78 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_80_2 = {6a 61 65 6d 69 6e 31 35 30 38 } 		$a_80_3 = {24 38 33 61 39 38 63 31 31 2d 35 39 62 38 2d 34 63 62 35 2d 38 31 36 33 2d 62 63 62 39 35 36 30 63 39 63 37 30 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}