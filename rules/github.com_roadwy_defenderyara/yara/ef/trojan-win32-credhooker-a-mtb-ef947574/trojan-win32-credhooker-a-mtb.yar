rule Trojan_Win32_CredHooker_A_MTB{
	meta:
		description = "Trojan:Win32/CredHooker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 31 30 36 2e 36 30 37 } 		$a_81_1 = {61 64 64 72 5f 77 73 61 63 6f 6e 6e 65 63 74 20 25 70 } 		$a_81_2 = {73 74 6f 70 69 6e 67 20 64 6c 6c } 		$a_81_3 = {31 32 37 2e 30 2e 30 2e 31 } 		$a_81_4 = {6c 6f 61 64 69 6e 67 20 64 6c 6c } 		$a_81_5 = {77 73 32 5f 33 32 2e 64 6c 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}