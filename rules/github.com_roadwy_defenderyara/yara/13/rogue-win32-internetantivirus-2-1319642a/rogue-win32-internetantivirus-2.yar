rule Rogue_Win32_InternetAntivirus_2{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 46 52 41 4d 45 5f 53 50 59 40 be ca 01 d4 5f 00 3f 14 80 cc c2 7e 56 49 52 55 53 3b 3f 17 58 } 		$a_01_1 = {cd 50 52 4f 20 43 e8 4c 52 27 16 0a 2c 5b a7 1e 52 52 56 bb 30 08 95 52 27 fe cb 02 e1 53 86 2d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}