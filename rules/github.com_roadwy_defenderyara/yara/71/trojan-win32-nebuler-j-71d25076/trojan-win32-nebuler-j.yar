rule Trojan_Win32_Nebuler_J{
	meta:
		description = "Trojan:Win32/Nebuler.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 53 53 4d 53 47 53 00 25 73 5c 25 73 00 00 00 50 49 44 00 4c 49 44 00 65 6d 70 74 79 00 00 00 5c 57 69 6e 49 6e 69 74 2e 49 6e 69 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}