rule Spyware_Win32_CnsMin{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 43 6e 73 4d 69 6e 4b 50 } 		$a_01_1 = {5c 5c 2e 5c 43 6e 73 4d 69 6e 4b 50 2e 56 78 64 } 		$a_01_2 = {25 73 63 6e 73 64 74 75 2e 63 61 62 } 		$a_01_3 = {25 73 33 37 32 31 5c 63 6e 73 31 2e 64 61 74 } 		$a_01_4 = {25 73 63 6e 73 2e 64 61 74 } 		$a_01_5 = {63 6e 73 31 75 2e 63 70 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}