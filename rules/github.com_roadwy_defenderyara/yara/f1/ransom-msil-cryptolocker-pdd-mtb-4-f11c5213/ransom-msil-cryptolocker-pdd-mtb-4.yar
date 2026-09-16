rule Ransom_MSIL_Cryptolocker_PDD_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 72 79 70 74 6f 6c 6f 63 6b 65 72 } 		$a_81_1 = {62 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } 		$a_81_2 = {4b 45 59 2e 63 72 79 70 74 6f 6c 6f 63 6b 65 72 } 		$a_81_3 = {52 65 63 6f 76 65 72 79 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}