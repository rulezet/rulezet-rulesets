rule Ransom_MSIL_Cryptolocker_DK_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } 		$a_81_1 = {43 52 41 43 4b 45 44 20 42 59 20 4d 41 4d 4f 34 33 34 33 37 36 } 		$a_81_2 = {52 45 41 44 5f 49 54 2e 74 78 74 2e 6c 6f 63 6b 65 64 } 		$a_81_3 = {77 61 6e 6e 61 64 69 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}