rule Trojan_Win32_Deepdo_3{
	meta:
		description = "Trojan:Win32/Deepdo,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 73 72 69 6e 69 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 		$a_01_1 = {2e 63 6e 2f 62 69 6e 2f 75 73 72 69 6e 69 74 2e 65 78 65 } 		$a_01_2 = {74 6e 3d 64 65 65 70 62 61 72 5f } 		$a_01_3 = {75 69 64 3d 25 73 26 75 72 6c 3d 25 73 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}