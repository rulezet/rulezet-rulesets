rule Backdoor_Win32_Plugx_K_dha{
	meta:
		description = "Backdoor:Win32/Plugx.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 45 f8 35 09 06 86 19 50 } 		$a_01_1 = {43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 77 00 61 00 76 00 } 		$a_01_2 = {7b 42 32 38 45 30 45 37 38 2d 38 38 32 44 2d 34 30 33 63 2d 41 46 34 45 2d 42 44 45 43 39 43 38 46 41 33 37 42 7d } 	condition:
		((#a_00_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=120
 
}