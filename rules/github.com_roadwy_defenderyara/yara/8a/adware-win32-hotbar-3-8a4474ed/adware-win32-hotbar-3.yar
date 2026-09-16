rule Adware_Win32_Hotbar_3{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 62 48 6f 73 74 49 45 2e 44 4c 4c 00 } 		$a_01_1 = {65 63 68 6f 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 73 6d 61 72 74 6f 66 66 65 72 73 } 		$a_01_2 = {55 70 67 72 61 64 65 53 6b 69 6e 53 79 73 74 65 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}