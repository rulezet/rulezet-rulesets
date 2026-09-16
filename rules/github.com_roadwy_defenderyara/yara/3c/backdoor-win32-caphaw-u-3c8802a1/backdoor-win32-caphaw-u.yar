rule Backdoor_Win32_Caphaw_U{
	meta:
		description = "Backdoor:Win32/Caphaw.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a9 00 00 f0 00 74 44 81 7d d4 47 65 6e 75 75 3b 81 7d d8 69 6e 65 49 75 32 81 7d dc 6e 74 65 6c 75 29 8b 45 e0 25 00 00 00 10 8b 4d f0 64 89 0d 00 00 00 00 } 		$a_01_1 = {8b 46 50 6a 40 50 53 ff d7 64 a1 10 00 00 00 8b 4e 50 6a 40 68 00 10 00 00 51 6a 00 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}