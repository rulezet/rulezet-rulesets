rule Backdoor_Win32_RDPopen_B{
	meta:
		description = "Backdoor:Win32/RDPopen.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 74 65 6d 50 25 00 63 73 72 73 73 72 2e 65 78 65 } 		$a_01_1 = {57 69 6e 64 6f 77 2d 52 50 43 20 48 6f 73 2d 53 65 72 76 69 63 65 } 		$a_02_2 = {2b c2 03 45 ?? 99 b9 1a 00 00 00 f7 f9 0f be 45 ?? 03 d0 8b 4d ?? 88 11 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}