rule Trojan_Win32_ICLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 c3 5a 00 ff 21 57 00 00 da 0a 00 73 5b 0d ca ac c1 56 00 00 d4 00 00 29 42 b3 73 } 		$a_01_1 = {4d 00 49 00 58 00 41 00 75 00 64 00 69 00 6f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}