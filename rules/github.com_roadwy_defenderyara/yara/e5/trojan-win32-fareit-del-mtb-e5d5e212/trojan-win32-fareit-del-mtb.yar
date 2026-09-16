rule Trojan_Win32_Fareit_DEL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {61 6e 6d 4e 38 32 73 4c 6a 52 } 		$a_81_1 = {49 43 31 39 75 31 35 4a 31 34 64 6e 37 52 34 4a 33 50 35 51 61 76 4a 39 62 55 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}