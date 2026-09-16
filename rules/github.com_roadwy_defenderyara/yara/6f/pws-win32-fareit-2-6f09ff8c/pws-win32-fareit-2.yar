rule PWS_Win32_Fareit_2{
	meta:
		description = "PWS:Win32/Fareit,SIGNATURE_TYPE_PEHSTR,16 00 16 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 57 44 46 49 4c 45 30 59 55 49 50 4b 44 46 49 4c 45 30 59 55 49 43 52 59 50 54 45 44 } 		$a_01_1 = {2f 67 61 74 65 2e 70 68 70 } 		$a_01_2 = {73 6f 66 74 77 61 72 65 5c 77 69 6e 72 61 72 00 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=22
 
}