rule Backdoor_Win32_Ananlog_A{
	meta:
		description = "Backdoor:Win32/Ananlog.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 61 00 73 00 74 00 5f 00 73 00 63 00 72 00 2b 00 } 		$a_01_1 = {6c 00 61 00 73 00 74 00 5f 00 75 00 70 00 6c 00 2b 00 70 00 69 00 63 00 64 00 69 00 72 00 5f 00 } 		$a_01_2 = {5c 00 30 00 2e 00 6b 00 65 00 79 00 6c 00 2d 00 } 		$a_01_3 = {72 00 65 00 6d 00 5f 00 6f 00 6c 00 64 00 5f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}