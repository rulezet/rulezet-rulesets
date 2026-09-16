rule Spyware_Win32_CnsMin_15{
	meta:
		description = "Spyware:Win32/CnsMin,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 73 69 73 74 5c 43 6e 73 4d 69 6e 4b 50 2e } 		$a_01_1 = {33 37 32 31 5c 41 73 73 69 73 74 5c 4d 6f 64 75 6c 65 73 } 		$a_01_2 = {43 61 74 63 68 53 65 78 53 74 79 6c 65 } 		$a_01_3 = {5c 6d 73 69 6e 66 6f 73 79 73 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}