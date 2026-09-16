rule Backdoor_Win32_Zegost_K{
	meta:
		description = "Backdoor:Win32/Zegost.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {b2 74 b1 5c 50 c6 44 24 ?? 53 c6 44 24 ?? 6f c6 44 24 ?? 66 } 		$a_02_1 = {b2 65 b0 73 51 c6 44 24 ?? 47 } 		$a_02_2 = {44 51 c6 44 24 ?? 65 c6 44 24 ?? 62 c6 44 24 ?? 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}