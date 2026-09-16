rule Ransom_MSIL_Cryptolocker_PDQ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 68 61 74 20 68 61 70 70 65 6e 20 74 6f 20 6d 79 20 66 69 6c 65 73 } 		$a_81_1 = {54 72 75 6d 70 4c 6f 63 6b 65 72 } 		$a_81_2 = {52 61 6e 73 6f 6d 4e 6f 74 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}