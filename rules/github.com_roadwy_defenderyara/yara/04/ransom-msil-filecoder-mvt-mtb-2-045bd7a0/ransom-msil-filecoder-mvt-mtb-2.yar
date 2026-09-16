rule Ransom_MSIL_FileCoder_MVT_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.MVT!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 61 71 69 70 61 78 6f 77 71 2e 65 78 65 } 		$a_01_1 = {5a 61 64 69 6c 6f 6b } 		$a_01_2 = {42 69 63 6c 61 76 65 6b } 		$a_01_3 = {43 6f 70 79 72 69 67 68 74 20 45 64 61 72 69 6d 65 6e 75 6d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}