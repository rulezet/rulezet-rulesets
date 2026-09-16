rule Virus_Win32_Sality_3{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_09_0 = {75 06 2b 0c 24 8d 7d 00 89 14 24 8d 49 ac } 		$a_09_1 = {33 db 53 4b 8d 40 73 f7 6c 24 68 52 } 		$a_03_2 = {2f 6c 6f 67 6f [0-01] 2e 67 69 66 } 	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}