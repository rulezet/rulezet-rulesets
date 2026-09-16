rule Ransom_MSIL_Cryptolocker_PDJ_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6e 65 74 40 73 68 20 40 66 69 72 40 65 77 61 40 6c 6c 20 73 65 40 74 20 6f 70 40 6d 6f 40 64 65 20 64 69 73 40 61 62 6c 65 } 		$a_81_1 = {52 61 6e 73 6f 6d } 		$a_81_2 = {68 75 72 72 79 20 68 75 72 72 79 20 68 75 72 72 79 } 		$a_81_3 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}