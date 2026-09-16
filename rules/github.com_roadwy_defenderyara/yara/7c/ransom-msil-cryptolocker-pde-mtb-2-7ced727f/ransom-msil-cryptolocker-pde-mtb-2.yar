rule Ransom_MSIL_Cryptolocker_PDE_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {44 61 72 6b 20 52 61 6e 73 6f 6d 65 77 61 72 65 } 		$a_81_2 = {50 6c 65 61 73 65 5f 52 65 61 64 2e 74 78 74 } 		$a_81_3 = {40 6d 61 69 6c 2e 63 6f 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}