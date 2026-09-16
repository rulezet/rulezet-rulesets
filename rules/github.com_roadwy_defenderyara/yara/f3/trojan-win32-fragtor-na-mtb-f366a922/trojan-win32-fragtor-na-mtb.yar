rule Trojan_Win32_Fragtor_NA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 69 64 77 66 5f 69 76 66 6f 72 75 } 		$a_81_1 = {62 75 79 79 64 5f 61 73 66 6f 64 76 } 		$a_81_2 = {63 76 79 64 75 65 5f 61 75 66 64 66 75 } 		$a_81_3 = {69 62 75 64 6f 64 5f 73 6f 64 6f 67 76 } 	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5) >=20
 
}