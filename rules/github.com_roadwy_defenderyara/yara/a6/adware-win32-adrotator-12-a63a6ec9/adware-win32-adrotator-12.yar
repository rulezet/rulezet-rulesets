rule Adware_Win32_AdRotator_12{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 42 72 6f 77 73 65 72 20 4f 70 74 69 6d 69 7a 65 72 20 41 64 73 73 69 74 65 } 		$a_01_1 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } 		$a_03_2 = {46 72 69 65 6e 64 6c 79 41 64 77 61 72 65 20 ?? ?? ?? 20 69 6e 73 74 61 6c 6c 65 64 21 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}