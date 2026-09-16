rule Backdoor_Win32_Zegost_CG{
	meta:
		description = "Backdoor:Win32/Zegost.CG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 80 04 11 da 03 ca 8b 4d fc 80 34 11 29 03 ca 42 3b d0 7c e9 } 		$a_01_1 = {c6 45 f4 48 c6 45 f5 61 c6 45 f6 63 c6 45 f7 6b c6 45 f8 65 c6 45 f9 72 } 		$a_01_2 = {c6 45 c6 50 c6 45 c7 72 c6 45 c8 6f c6 45 c9 63 c6 45 ca 65 c6 45 cb 73 c6 45 cc 73 c6 45 cd 49 c6 45 ce 64 88 5d cf ff d6 50 ff d7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}