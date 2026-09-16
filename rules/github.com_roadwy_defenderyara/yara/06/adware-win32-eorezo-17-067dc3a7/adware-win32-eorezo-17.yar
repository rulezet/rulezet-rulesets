rule Adware_Win32_Eorezo_17{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 64 73 2e 65 6f 72 65 7a 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 61 64 76 65 72 74 2f 67 65 74 61 64 73 2e 63 67 69 3f } 		$a_01_1 = {41 76 65 72 74 69 73 73 65 6d 65 6e 74 20 64 65 } 		$a_01_2 = {6a 00 6a 64 68 ea 03 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}