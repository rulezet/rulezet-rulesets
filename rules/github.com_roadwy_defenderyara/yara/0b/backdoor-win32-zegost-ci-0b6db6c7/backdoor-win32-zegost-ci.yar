rule Backdoor_Win32_Zegost_CI{
	meta:
		description = "Backdoor:Win32/Zegost.CI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 26 25 73 20 22 25 73 22 } 		$a_01_1 = {25 73 20 22 25 73 22 2c 43 72 65 61 74 65 46 6c 61 73 68 41 64 61 70 74 65 72 20 25 73 } 		$a_01_2 = {20 25 2e 32 66 6d 73 2c 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}