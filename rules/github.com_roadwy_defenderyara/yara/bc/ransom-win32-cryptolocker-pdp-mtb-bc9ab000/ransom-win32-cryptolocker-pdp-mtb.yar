rule Ransom_Win32_Cryptolocker_PDP_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 61 43 72 79 70 74 30 72 } 		$a_81_1 = {2e 77 6e 72 79 } 		$a_81_2 = {57 41 4e 41 43 52 59 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}