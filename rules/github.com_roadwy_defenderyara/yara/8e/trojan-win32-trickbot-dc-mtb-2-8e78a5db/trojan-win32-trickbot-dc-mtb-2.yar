rule Trojan_Win32_TrickBot_DC_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 65 72 2e 64 6c 6c } 		$a_81_1 = {43 72 79 70 74 65 72 2e 70 64 62 } 		$a_81_2 = {64 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } 		$a_81_3 = {2e 30 30 63 66 67 } 		$a_81_4 = {5f 6d 66 45 77 56 4b 41 47 4f 41 54 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}