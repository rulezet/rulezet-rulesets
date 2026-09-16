rule Ransom_Win32_Cryptolocker_PDR_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 61 62 79 44 6f 6e 74 48 65 61 72 74 4d 65 } 		$a_81_1 = {77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 } 		$a_81_2 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } 		$a_81_3 = {54 6f 72 20 42 72 6f 77 73 65 72 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}