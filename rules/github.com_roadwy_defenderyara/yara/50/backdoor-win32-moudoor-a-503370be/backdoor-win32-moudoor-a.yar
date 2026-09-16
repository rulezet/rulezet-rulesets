rule Backdoor_Win32_Moudoor_A{
	meta:
		description = "Backdoor:Win32/Moudoor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e 20 [0-02] 20 26 20 64 65 6c 20 22 25 73 22 } 		$a_03_1 = {c3 33 c9 85 ff 76 1e 8b c1 bd 06 00 00 00 99 f7 fd 8a 04 31 80 c2 ?? 32 c2 88 04 31 41 3b cf 72 e6 8b 6c 24 ?? 8d 44 24 ?? 6a 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}