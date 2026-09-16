rule Trojan_Win32_Malgent_RP_MTB{
	meta:
		description = "Trojan:Win32/Malgent.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,70 00 70 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 5c 74 65 73 74 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 31 2e 70 64 62 } 		$a_01_1 = {45 00 6e 00 73 00 75 00 70 00 2e 00 6c 00 6f 00 67 00 } 		$a_01_2 = {53 69 67 6e 61 6c 43 68 72 6f 6d 65 45 6c 66 } 		$a_01_3 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=112
 
}