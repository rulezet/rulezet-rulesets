rule Ransom_MSIL_Cryptolocker_PDN_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {44 45 43 52 59 50 54 20 4d 59 20 46 49 4c 45 53 } 		$a_81_2 = {2f 43 20 73 63 20 64 65 6c 65 74 65 20 56 53 53 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}