rule Backdoor_Win32_Conpee_A{
	meta:
		description = "Backdoor:Win32/Conpee.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 65 65 72 43 6f 6e 6e 5e 5f 5e 4d 65 32 } 		$a_01_1 = {6d 73 70 61 74 63 68 2e 64 6c 6c 00 77 75 61 75 73 65 72 76 } 		$a_03_2 = {8b 55 08 03 55 fc 0f be 02 83 e8 ?? 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f be 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}