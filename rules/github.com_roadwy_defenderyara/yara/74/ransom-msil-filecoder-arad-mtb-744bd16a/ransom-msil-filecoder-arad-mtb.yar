rule Ransom_MSIL_Filecoder_ARAD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {69 6e 73 65 72 74 20 79 6f 75 72 20 62 69 63 6f 69 6e 20 61 64 72 65 73 73 20 68 65 72 65 } 		$a_80_1 = {68 6f 77 20 74 6f 20 72 65 6d 6f 76 65 20 63 72 79 70 74 6f 6c 6f 63 6b 65 72 } 		$a_80_2 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 21 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}