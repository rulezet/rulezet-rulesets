rule Ransom_MSIL_Cryptolocker_PDK_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 } 		$a_81_1 = {5f 45 6e 63 72 79 70 74 65 64 24 } 		$a_81_2 = {56 32 6c 75 5a 47 39 33 63 30 5a 76 63 6d 31 7a 51 58 42 77 4d 53 55 3d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}