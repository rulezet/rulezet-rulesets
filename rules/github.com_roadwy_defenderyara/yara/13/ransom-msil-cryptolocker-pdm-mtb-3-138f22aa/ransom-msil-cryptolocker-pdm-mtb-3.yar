rule Ransom_MSIL_Cryptolocker_PDM_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } 		$a_81_2 = {2e 6c 6f 63 6b 65 64 } 		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}