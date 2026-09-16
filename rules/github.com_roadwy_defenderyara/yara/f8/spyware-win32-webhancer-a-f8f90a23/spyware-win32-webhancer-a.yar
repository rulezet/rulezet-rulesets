rule Spyware_Win32_WebHancer_A{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 68 69 65 73 68 6d 2e 64 6c 6c } 		$a_01_1 = {77 68 41 67 65 6e 74 2e 65 78 65 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } 		$a_01_3 = {77 68 69 65 68 6c 70 72 2e 64 6c 6c } 		$a_01_4 = {77 68 69 65 64 63 2e 53 54 41 54 49 43 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*6) >=15
 
}