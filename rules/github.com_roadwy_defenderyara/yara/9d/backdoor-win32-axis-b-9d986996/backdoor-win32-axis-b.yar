rule Backdoor_Win32_Axis_B{
	meta:
		description = "Backdoor:Win32/Axis.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f } 		$a_01_1 = {40 6d 6d 70 72 73 } 		$a_01_2 = {41 58 49 53 } 		$a_01_3 = {70 72 65 6d 69 75 6d } 		$a_01_4 = {2f 66 69 6c 65 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=9
 
}