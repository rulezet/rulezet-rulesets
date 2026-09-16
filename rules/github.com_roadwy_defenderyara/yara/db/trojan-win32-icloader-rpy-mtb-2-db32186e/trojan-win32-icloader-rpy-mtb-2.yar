rule Trojan_Win32_ICLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 55 6c 00 fa b3 68 00 00 da 0a 00 73 5b 0d ca 37 3e 68 00 00 d4 00 00 4d 7d f5 28 } 		$a_01_1 = {41 00 75 00 64 00 69 00 6f 00 53 00 77 00 69 00 74 00 63 00 68 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}