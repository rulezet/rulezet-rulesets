rule Adware_Win32_AdRotator_6{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 37 44 44 45 45 39 46 2d 43 44 34 42 2d 34 30 66 62 2d 39 30 33 30 2d 45 31 37 30 39 36 34 34 46 34 42 44 7d } 		$a_01_1 = {77 61 76 65 2e 53 68 44 6c 20 3d 20 73 20 27 77 61 76 65 } 		$a_01_2 = {70 69 6f 31 32 00 00 70 6f 74 79 00 00 00 00 71 75 69 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}