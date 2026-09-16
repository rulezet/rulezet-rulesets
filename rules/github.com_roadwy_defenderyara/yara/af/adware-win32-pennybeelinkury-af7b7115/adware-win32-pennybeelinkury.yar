rule Adware_Win32_PennyBeeLinkury{
	meta:
		description = "Adware:Win32/PennyBeeLinkury,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 49 6e 6a 65 63 74 41 70 70 00 44 6c 6c 49 6e 6a 65 63 74 69 6f 6e 52 65 73 75 6c 74 00 44 6c 6c 49 6e 6a 65 63 74 6f 72 00 } 		$a_03_1 = {5c 4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 5c 53 6d 61 72 74 62 61 72 2e 4d 6f 6e 65 74 69 7a 61 74 69 6f 6e 2e 49 6e 6a 65 63 74 41 70 70 5c 6f 62 6a [0-04] 5c 52 65 6c 65 61 73 65 5c 73 6d 69 61 2e 70 64 62 } 		$a_01_2 = {6e 00 74 00 64 00 69 00 73 00 5f 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}