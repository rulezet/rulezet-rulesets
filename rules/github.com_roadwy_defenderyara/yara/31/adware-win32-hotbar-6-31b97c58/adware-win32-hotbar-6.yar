rule Adware_Win32_Hotbar_6{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 6f 74 62 61 72 53 41 48 6f 6f 6b 2e 64 6c 6c 00 } 		$a_01_1 = {73 65 65 6b 6d 6f 73 61 7c 7a 61 6e 67 6f 73 61 7c 73 62 75 73 61 7c 68 6f 74 62 61 72 73 61 } 		$a_01_2 = {25 73 20 53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}