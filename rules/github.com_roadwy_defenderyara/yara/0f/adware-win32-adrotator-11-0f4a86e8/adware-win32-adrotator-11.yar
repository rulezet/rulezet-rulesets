rule Adware_Win32_AdRotator_11{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 41 31 41 34 46 38 33 2d 42 34 41 43 2d 34 38 35 39 2d 38 43 39 31 2d 32 31 44 42 45 36 43 35 36 32 35 42 7d } 		$a_01_1 = {63 6f 72 65 2e 49 63 6f 6e 69 7a 65 72 20 3d 20 73 20 27 49 63 6f 6e 69 7a 65 72 } 		$a_01_2 = {61 64 76 65 72 74 3a 2f 2f 61 64 76 65 72 74 73 65 72 76 65 72 2e 63 6f 6d 2f 25 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}