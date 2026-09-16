rule Adware_Win32_Lollipop_8{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 72 65 65 53 65 78 50 6c 61 79 65 72 41 70 70 40 40 } 		$a_01_1 = {3c 66 73 70 5f 70 61 72 61 6d 73 3e 00 } 		$a_01_2 = {4c 00 6f 00 6c 00 6c 00 69 00 70 00 6f 00 70 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}