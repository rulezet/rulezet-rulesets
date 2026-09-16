rule Ransom_MSIL_Cryptolocker_PDK_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {50 65 6e 74 61 20 72 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_2 = {57 69 72 75 73 69 6b 5f 52 61 6e 73 6f 6d } 		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}