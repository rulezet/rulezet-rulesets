rule Ransom_MSIL_Samas_D{
	meta:
		description = "Ransom:MSIL/Samas.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 9a 0c 08 20 80 00 00 00 28 59 00 00 0a 08 28 3e 00 00 0a 11 05 17 58 13 05 } 		$a_01_1 = {00 09 53 00 41 00 4c 00 54 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=10
 
}