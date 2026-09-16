rule Trojan_Win32_Fareit_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {56 5f 69 5f 72 5f 74 5f 75 5f 61 5f 6c 5f 50 5f 72 5f 6f 5f 74 5f 65 5f 63 5f 74 5f } 		$a_81_1 = {43 32 72 32 79 32 70 32 74 32 44 32 65 32 73 32 74 32 72 32 6f 32 79 32 4b 32 65 32 79 32 } 		$a_81_2 = {56 44 69 44 72 44 74 44 75 44 61 44 6c 44 41 44 6c 44 6c 44 6f 44 63 44 45 44 78 44 } 		$a_81_3 = {6f 77 65 64 6d 65 73 61 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}