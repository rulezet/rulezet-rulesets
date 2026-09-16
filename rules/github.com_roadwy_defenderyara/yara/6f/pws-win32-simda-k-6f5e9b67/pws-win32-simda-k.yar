rule PWS_Win32_Simda_K{
	meta:
		description = "PWS:Win32/Simda.K,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c } 		$a_01_1 = {62 6f 74 69 64 3d 25 73 26 76 65 72 3d } 		$a_01_2 = {73 6c 69 70 6b 6e 6f 74 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}