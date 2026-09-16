rule Adware_Win32_AdRotator{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 00 72 00 77 00 73 00 72 00 5f 00 } 		$a_01_1 = {66 00 72 00 6f 00 6d 00 61 00 74 00 65 00 64 00 } 		$a_01_2 = {64 72 63 74 00 00 00 00 65 6e 63 00 65 6e 62 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}