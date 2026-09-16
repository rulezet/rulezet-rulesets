rule Backdoor_Win32_Linfo_A{
	meta:
		description = "Backdoor:Win32/Linfo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 03 7d f8 8a 07 c0 c8 05 34 21 88 07 41 3b ce 89 4d f8 7c e9 } 		$a_01_1 = {5c 74 70 2e 64 61 74 00 00 00 65 78 46 6f 72 6d 00 00 6c 69 6e 6b 69 6e 66 6f 2e 64 6c 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}