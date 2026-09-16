rule Trojan_Win32_Fragtor_ARR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 61 64 6d 79 44 6c 6c } 		$a_81_1 = {73 74 72 61 74 20 72 75 6e } 		$a_81_2 = {49 4f 4a 43 4d 61 69 6e } 	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*4+(#a_81_2  & 1)*10) >=20
 
}