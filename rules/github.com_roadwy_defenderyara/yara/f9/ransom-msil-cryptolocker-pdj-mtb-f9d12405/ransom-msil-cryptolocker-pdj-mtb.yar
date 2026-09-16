rule Ransom_MSIL_Cryptolocker_PDJ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {68 69 64 64 65 6e 20 74 65 61 72 } 		$a_81_2 = {48 41 4e 54 41 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}