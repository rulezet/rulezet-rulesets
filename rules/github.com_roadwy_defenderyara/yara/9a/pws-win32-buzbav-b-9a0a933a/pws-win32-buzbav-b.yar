rule PWS_Win32_Buzbav_B{
	meta:
		description = "PWS:Win32/Buzbav.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 b9 40 00 00 00 33 c0 8d 7c 24 ?? c6 44 24 ?? 00 f3 ab 66 ab aa b9 ff 01 00 00 33 c0 8d bc 24 ?? 01 00 00 c6 84 24 ?? 01 00 00 00 f3 ab 66 ab aa b9 ?? 00 00 00 } 		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 64 6c 6c [0-10] 53 45 52 56 45 52 [0-15] 40 65 78 69 74 00 40 64 65 6c [0-30] 2e 61 71 71 } 	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}