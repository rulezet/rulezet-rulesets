rule Adware_Win32_Eorezo_2{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 64 73 2e 65 6f 72 65 7a 6f 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 61 64 76 65 72 74 2f 67 65 74 61 64 73 } 		$a_01_1 = {5c 45 6f 45 6e 67 69 6e 65 2e 65 78 65 00 00 00 53 6f 66 74 77 61 72 65 5c 45 6f 52 65 7a 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}