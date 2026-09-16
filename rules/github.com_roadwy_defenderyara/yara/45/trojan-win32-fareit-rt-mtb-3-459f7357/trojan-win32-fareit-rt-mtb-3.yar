rule Trojan_Win32_Fareit_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 75 6d 65 6e 61 78 6b 65 77 65 72 61 6e 73 6b 78 6d 65 } 		$a_01_1 = {74 78 74 50 61 73 73 77 6f 72 64 } 		$a_01_2 = {77 61 6e 75 6d 65 73 66 72 73 63 73 61 73 66 76 32 } 		$a_01_3 = {61 72 65 6e 61 6f 73 6b 75 6d 6e 66 73 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}