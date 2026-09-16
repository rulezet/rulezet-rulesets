rule Trojan_Win32_Emotet_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 6e 63 6f 78 6b 6d } 		$a_81_1 = {61 75 6b 6a 62 7a 64 6c 6f 71 71 72 66 76 } 		$a_81_2 = {61 75 78 69 67 75 67 6d 66 74 6e 78 6f } 		$a_81_3 = {63 6b 79 77 65 67 6d 74 6b 76 74 63 73 6e } 		$a_81_4 = {65 71 71 75 64 71 6b 64 76 71 6a 62 78 76 70 77 6d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}