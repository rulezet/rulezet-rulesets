rule Ransom_MSIL_Filecoder_ARAF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 68 65 6c 6c 4c 6f 63 6b 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 5c 53 68 65 6c 6c 4c 6f 63 6b 65 72 5c 53 68 65 6c 6c 4c 6f 63 6b 65 72 5c 62 69 6e 5c 53 68 65 6c 6c 4c 6f 63 6b 65 72 2e 70 64 62 } 		$a_80_1 = {4b 65 79 62 6f 61 72 64 20 68 6f 6f 6b 65 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}