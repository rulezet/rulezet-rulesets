rule Adware_Win32_Hotbar_44{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5f 73 61 5c 42 69 6e 5c 52 65 6c 65 61 73 65 5c 53 65 74 75 70 2e 70 64 62 } 		$a_01_1 = {53 6d 61 72 74 20 53 68 6f 70 70 65 72 } 		$a_01_2 = {5a 61 6e 67 6f } 		$a_01_3 = {61 70 70 62 75 6e 64 6c 65 72 2e 63 6f 6d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}