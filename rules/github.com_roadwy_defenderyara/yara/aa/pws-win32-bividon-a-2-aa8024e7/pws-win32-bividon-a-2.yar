rule PWS_Win32_Bividon_A_2{
	meta:
		description = "PWS:Win32/Bividon.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 54 1a ff 80 f2 e9 88 54 18 ff 43 4e 75 e6 } 		$a_01_1 = {bb 01 00 00 00 8d 45 ec 50 b9 01 00 00 00 8b d3 8b c7 } 		$a_01_2 = {77 69 6e 6b 00 } 		$a_01_3 = {80 38 01 75 0c 68 00 ba db 00 e8 } 		$a_01_4 = {2d 93 08 00 00 74 0c 2d 95 01 00 00 74 36 } 		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3) >=7
 
}