rule Adware_Win32_Eorezo_16{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 66 2e 65 6f 72 65 7a 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f } 		$a_01_1 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 20 2d 43 6c 61 73 73 20 41 6e 74 69 56 69 72 75 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}