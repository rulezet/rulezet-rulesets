rule Adware_Win32_AdRotator_3{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 52 4f 4e 20 54 6f 6f 31 } 		$a_01_1 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } 		$a_03_2 = {61 66 66 5f 69 64 [0-06] 62 32 73 65 61 72 63 68 00 64 65 66 61 75 6c 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}