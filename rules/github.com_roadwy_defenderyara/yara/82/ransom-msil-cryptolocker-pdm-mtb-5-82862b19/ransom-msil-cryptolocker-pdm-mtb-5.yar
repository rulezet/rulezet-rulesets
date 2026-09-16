rule Ransom_MSIL_Cryptolocker_PDM_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 4c 69 73 74 } 		$a_81_1 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } 		$a_81_2 = {59 6f 75 72 20 50 63 20 68 61 76 65 20 62 65 65 6e 20 66 75 63 6b 65 64 } 		$a_81_3 = {44 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}