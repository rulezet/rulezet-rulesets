rule Adware_Win32_Lollipop_9{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 4c 6f 6c 6c 69 70 6f 70 46 75 6e 63 40 40 } 		$a_01_1 = {2e 3f 41 56 42 61 73 65 4c 50 40 40 } 		$a_01_2 = {6f 00 6e 00 41 00 63 00 63 00 65 00 73 00 73 00 53 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}