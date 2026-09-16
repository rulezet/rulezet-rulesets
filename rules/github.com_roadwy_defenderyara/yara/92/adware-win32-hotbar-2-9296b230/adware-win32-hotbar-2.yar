rule Adware_Win32_Hotbar_2{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 5c 53 6f 75 72 63 65 5c 31 38 30 53 41 2e 63 70 70 } 		$a_01_1 = {31 38 30 73 61 7c 31 38 30 61 64 73 6f 6c 75 74 69 6f 6e } 		$a_01_2 = {2f 73 68 6f 77 5f 61 64 73 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}