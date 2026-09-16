rule PWS_Win32_Lolyda_BF{
	meta:
		description = "PWS:Win32/Lolyda.BF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 75 63 6f 6d 72 65 73 2e 64 6c 6c 00 00 00 00 79 75 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 00 00 79 75 6b 73 75 73 65 72 2e 64 6c 6c 00 } 		$a_01_1 = {53 50 8d 45 cc 6a 15 50 ff 75 e8 ff d7 6a 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}