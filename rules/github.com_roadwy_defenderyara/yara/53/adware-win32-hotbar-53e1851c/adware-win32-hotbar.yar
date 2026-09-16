rule Adware_Win32_Hotbar{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {76 69 63 70 61 72 61 6d 65 74 65 72 73 } 		$a_00_1 = {64 65 66 62 72 6f 77 73 65 72 3d } 		$a_01_2 = {8b 4e 1c 8b 56 10 53 53 51 52 53 ff d0 3b c3 7d } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}