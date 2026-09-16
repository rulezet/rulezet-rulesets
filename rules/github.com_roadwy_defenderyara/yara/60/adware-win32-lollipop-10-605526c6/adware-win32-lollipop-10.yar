rule Adware_Win32_Lollipop_10{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 42 61 73 65 4c 50 40 40 } 		$a_01_1 = {49 4e 53 54 41 4c 4c 3a 7c 31 34 36 39 33 7c 7c 38 36 34 30 30 7c 31 7c 30 30 30 37 7c 7c } 		$a_01_2 = {2e 3f 41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } 		$a_01_3 = {4c 6f 6c 6c 69 70 6f 70 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*6+(#a_01_3  & 1)*5) >=18
 
}