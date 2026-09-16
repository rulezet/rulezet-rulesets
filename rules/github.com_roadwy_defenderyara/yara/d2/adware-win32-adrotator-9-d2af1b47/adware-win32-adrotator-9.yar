rule Adware_Win32_AdRotator_9{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 36 30 35 34 38 34 31 2d 35 35 35 36 2d 34 37 34 38 2d 38 46 36 45 2d 41 41 44 33 37 44 42 34 41 30 36 43 7d } 		$a_01_1 = {46 61 73 74 52 58 2e 43 75 73 74 6f 6d 52 58 20 3d 20 73 20 27 43 75 73 74 6f 6d 52 58 } 		$a_01_2 = {66 61 73 74 72 78 00 6d 6d 70 00 62 79 61 7a 6f 6d 79 61 7a 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}