rule Adware_Win32_Eorezo_3{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 66 2e 65 6f 72 65 7a 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 70 61 63 6b 61 67 65 73 2f 44 59 4e 50 41 43 4b 41 47 45 53 5f 57 45 42 5f 47 45 54 5f 49 4e 46 4f } 		$a_01_1 = {3f 73 64 61 74 65 67 2f 74 72 65 76 64 61 2f 6e 69 62 2d 69 67 63 2f 6d 6f 63 2e 62 75 70 65 64 65 69 67 65 72 2e 73 64 61 2f 2f 3a 70 74 74 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}