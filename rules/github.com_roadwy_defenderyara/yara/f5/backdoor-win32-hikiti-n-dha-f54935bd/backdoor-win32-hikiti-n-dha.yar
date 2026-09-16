rule Backdoor_Win32_Hikiti_N_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.N!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 65 76 69 6c 2d 63 6f 64 65 73 5c 62 69 6e 5c 78 56 69 72 75 73 2e 70 64 62 00 } 		$a_01_1 = {c1 e8 02 40 8b d0 c1 e2 02 2b ca 8b f9 31 1e 83 c6 04 48 75 f8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}