rule Backdoor_Win32_Moudoor_B{
	meta:
		description = "Backdoor:Win32/Moudoor.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 31 41 3b cf 72 ed 8d 45 } 		$a_01_1 = {8b c1 6a 06 99 5b f7 fb 80 c2 66 30 14 39 41 3b 4d } 		$a_01_2 = {75 70 2e 62 61 6b 00 00 55 70 64 61 74 65 57 69 6e 64 6f 77 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}