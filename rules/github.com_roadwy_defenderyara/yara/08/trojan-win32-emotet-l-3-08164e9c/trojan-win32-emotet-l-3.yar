rule Trojan_Win32_Emotet_L_3{
	meta:
		description = "Trojan:Win32/Emotet.L,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 71 00 6b 00 53 00 4b 00 7a 00 51 00 61 00 6d 00 44 00 6b 00 73 00 75 00 59 00 67 00 75 00 } 		$a_01_1 = {67 77 48 4a 6c 39 4c 4c 77 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}