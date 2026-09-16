rule Ransom_MSIL_Cryptolocker_PDL_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 43 20 73 63 20 64 65 6c 65 74 65 20 56 53 53 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {6b 57 59 5a 72 7a 49 59 5a 52 2e 68 74 6d 6c } 		$a_81_3 = {72 64 70 75 6e 6c 6f 63 6b 65 72 31 40 63 6f 63 6b 2e 6c 69 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}