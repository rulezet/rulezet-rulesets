rule Backdoor_Win32_Protux_B_dll{
	meta:
		description = "Backdoor:Win32/Protux.B!dll,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 20 48 54 54 50 2f 31 2e 31 } 		$a_01_1 = {48 54 54 50 48 65 61 64 65 72 3a 25 73 2c 6e 52 65 63 76 65 64 3a 25 64 } 		$a_01_2 = {68 6f 6e 67 7a 69 6e 73 74 00 00 00 6a 71 79 2e 64 61 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=10
 
}