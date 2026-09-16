rule Ransom_MSIL_Cryptolocker_PDN_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 72 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_1 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 4c 69 73 74 } 		$a_81_2 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}