rule Ransom_MSIL_FileCoder_AF_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 0e 16 13 0f 2b 17 11 0e 11 0f 9a 13 10 00 11 10 28 07 00 00 06 00 00 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 e1 } 		$a_01_1 = {4d 61 7a 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4d 61 7a 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}