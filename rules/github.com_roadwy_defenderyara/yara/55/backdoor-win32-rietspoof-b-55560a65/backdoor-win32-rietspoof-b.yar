rule Backdoor_Win32_Rietspoof_B{
	meta:
		description = "Backdoor:Win32/Rietspoof.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 fc ff ff ff 2b c7 83 e0 07 8b 34 82 b8 fe ff ff ff 2b c7 83 e0 07 8b 0c 82 8b c7 f7 d0 83 e0 07 8d 1c 82 8b d6 c1 ca 0b 8b c6 c1 c0 07 33 d0 } 		$a_00_1 = {4d 39 68 35 61 6e 38 66 38 7a 54 6a 6e 79 54 77 51 56 68 36 68 59 42 64 59 73 4d 71 48 69 41 7a 00 } 		$a_02_2 = {73 79 73 74 65 6d 0a 00 [0-06] 25 73 25 73 25 73 20 55 53 45 52 3a 20 75 73 65 72 0a 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2+(#a_02_2  & 1)*1) >=2
 
}