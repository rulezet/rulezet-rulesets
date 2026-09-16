rule Trojan_Win32_Fareit_DEL_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {38 6e 54 62 63 6c 42 4c 62 55 7a 69 58 31 42 58 63 6b 74 33 52 71 61 37 57 53 4d 32 64 39 4b 4a 6e 56 4c 63 48 55 44 } 		$a_81_1 = {43 66 42 39 39 61 65 7a 65 34 4f 77 } 		$a_81_2 = {36 33 37 32 57 52 36 69 6a 4f 34 44 77 54 77 61 41 6c 72 4c 6c 79 75 4a } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}