rule Ransom_MSIL_Cryptolocker_PDJ_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } 		$a_81_1 = {2e 45 6e 63 72 79 70 74 65 64 } 		$a_81_2 = {59 6f 75 72 20 42 54 43 20 41 64 64 72 65 73 73 } 		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}