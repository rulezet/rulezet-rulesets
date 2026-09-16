rule Ransom_MSIL_Cryptolocker_PDO_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {4a 65 73 75 73 20 52 61 6e 73 6f 6d } 		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}