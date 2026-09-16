rule Ransom_Win32_Cryptolocker_PDP_MTB_2{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {53 63 6f 72 70 69 6f 6e 45 6e 63 72 79 70 74 69 6f 6e } 		$a_81_2 = {52 65 61 64 2d 4d 65 2d 4e 6f 77 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}