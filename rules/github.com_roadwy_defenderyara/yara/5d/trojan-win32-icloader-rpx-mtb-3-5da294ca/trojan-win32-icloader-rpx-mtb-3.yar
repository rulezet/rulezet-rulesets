rule Trojan_Win32_ICLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 87 33 00 25 e6 2f 00 00 da 0a 00 73 5b 0d ca 92 aa 2f 00 00 d4 00 00 55 63 05 9b } 		$a_01_1 = {51 00 74 00 35 00 4f 00 70 00 65 00 6e 00 47 00 4c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}