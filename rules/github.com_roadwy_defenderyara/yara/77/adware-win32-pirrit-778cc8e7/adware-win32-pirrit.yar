rule Adware_Win32_Pirrit{
	meta:
		description = "Adware:Win32/Pirrit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 63 68 65 63 6b 41 6e 64 52 75 6e 50 69 72 72 69 74 28 29 } 		$a_01_1 = {50 69 72 72 69 74 44 65 73 6b 74 6f 70 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}