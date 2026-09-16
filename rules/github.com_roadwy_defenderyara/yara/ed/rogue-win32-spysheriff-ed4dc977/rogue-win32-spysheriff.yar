rule Rogue_Win32_SpySheriff{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 61 6c 77 61 72 65 42 65 6c 6c 2e 63 6f 6d } 		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 73 74 69 6c 6c 20 69 6e 66 65 63 74 65 64 21 20 41 72 65 20 79 6f 75 20 73 75 72 65 20 74 6f 20 65 78 69 74 20 6e 6f 77 3f } 		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}