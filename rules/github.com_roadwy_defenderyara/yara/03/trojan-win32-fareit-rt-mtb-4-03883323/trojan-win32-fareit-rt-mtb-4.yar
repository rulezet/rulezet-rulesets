rule Trojan_Win32_Fareit_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {36 2f 2f 2f 2f 36 2f 36 31 36 36 31 } 		$a_81_1 = {50 72 6f 6c 6f 67 6b 6c 61 75 73 75 6c 65 6e 73 35 } 		$a_81_2 = {46 6f 72 66 6c 79 74 74 65 6c 73 65 72 6e 65 73 37 } 		$a_81_3 = {4d 69 6c 6a 62 65 73 6b 79 74 74 65 6c 73 65 73 72 65 67 6c 65 6d 65 6e 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}