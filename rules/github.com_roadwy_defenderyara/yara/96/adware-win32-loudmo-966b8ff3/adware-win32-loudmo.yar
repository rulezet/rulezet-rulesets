rule Adware_Win32_Loudmo{
	meta:
		description = "Adware:Win32/Loudmo,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 77 00 41 00 64 00 42 00 72 00 46 00 72 00 6d 00 } 		$a_01_1 = {6d 00 75 00 73 00 65 00 75 00 6d 00 } 		$a_01_2 = {41 00 64 00 77 00 41 00 64 00 57 00 6e 00 64 00 } 		$a_02_3 = {2a 0c 3a 99 f7 fe 8a c1 8a 0d ?? ?? ?? ?? fe c1 f6 2c 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*10) >=12
 
}