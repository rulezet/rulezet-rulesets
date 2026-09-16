rule Ransom_MSIL_Filecoder_ARAF_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 74 61 72 74 52 61 6e 73 2e 62 61 74 } 		$a_01_1 = {5c 72 65 63 6f 76 65 72 79 4b 65 79 2e 74 78 74 } 		$a_01_2 = {5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 74 61 72 74 56 73 2e 62 61 74 } 		$a_01_3 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}