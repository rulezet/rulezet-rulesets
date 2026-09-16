rule BrowserModifier_Win32_Zwangi_52{
	meta:
		description = "BrowserModifier:Win32/Zwangi,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 53 70 61 63 65 51 75 65 72 79 5f 49 6e 73 74 5f 6d 74 78 22 29 } 		$a_01_1 = {3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 53 70 61 63 65 51 75 65 72 79 5f 55 6e 69 6e 73 74 5f 6d 74 78 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}