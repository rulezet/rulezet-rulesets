rule Backdoor_Win32_CarpeDiem_3{
	meta:
		description = "Backdoor:Win32/CarpeDiem,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 70 77 61 74 63 68 77 69 6e 73 68 6f 65 6e 6f 6c 6f 67 } 		$a_01_1 = {53 6f 66 74 57 61 72 65 5c 43 61 72 70 65 44 69 65 6d 56 61 72 73 5c 4b 69 74 5c } 		$a_01_2 = {64 69 61 6c 75 70 2e 63 61 72 70 65 64 69 65 6d 2e } 		$a_01_3 = {70 65 72 6c 2f 63 6f 75 6e 74 64 69 61 6c 75 70 69 6e 74 65 72 2e 70 6c 3f 6e 61 6d 65 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}