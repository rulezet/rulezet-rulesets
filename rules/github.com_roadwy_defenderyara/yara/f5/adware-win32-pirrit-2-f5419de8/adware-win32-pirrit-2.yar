rule Adware_Win32_Pirrit_2{
	meta:
		description = "Adware:Win32/Pirrit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 66 69 6e 69 73 68 65 64 44 6f 77 6e 6c 6f 61 64 49 6e 6a 65 63 74 69 6f 6e 43 6f 6e 74 65 6e 74 28 51 4e 65 74 77 6f 72 6b } 		$a_01_1 = {76 61 72 20 70 72 74 4c 6f 61 64 65 72 } 		$a_01_2 = {66 75 6e 63 74 69 6f 6e 20 70 72 74 49 6e 49 66 72 61 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}