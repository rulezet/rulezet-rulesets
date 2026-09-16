rule Trojan_Win32_Gozi_BB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {b9 04 00 00 00 6b d1 14 b8 04 00 00 00 6b c8 06 [0-15] 81 fa dc 02 00 00 } 		$a_81_1 = {44 72 69 76 65 2e 64 6c 6c } 		$a_81_2 = {43 6c 6f 63 6b 63 6f 6e 64 69 74 69 6f 6e } 		$a_81_3 = {44 6f 67 77 68 65 6e } 		$a_81_4 = {53 69 6e 67 } 		$a_81_5 = {57 68 6f 6c 65 67 72 61 79 } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}