rule Ransom_MSIL_Yodaware_C_2{
	meta:
		description = "Ransom:MSIL/Yodaware.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 78 00 52 00 78 00 4f 00 78 00 43 00 78 00 4d 00 78 00 4f 00 78 00 4e 00 78 00 } 		$a_01_1 = {46 00 75 00 73 00 69 00 6f 00 6e 00 20 00 4c 00 6f 00 67 00 3a 00 } 		$a_01_2 = {68 65 6c 6c 6f 77 6f 72 6c 64 2e 70 72 2e 74 78 74 } 		$a_01_3 = {5c 24 53 79 73 52 65 73 65 74 5c 4c 6f 67 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}