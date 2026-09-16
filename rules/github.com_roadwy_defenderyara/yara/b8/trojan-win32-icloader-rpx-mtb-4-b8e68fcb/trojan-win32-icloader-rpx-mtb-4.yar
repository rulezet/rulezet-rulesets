rule Trojan_Win32_ICLoader_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9d 7a 74 00 14 df 70 00 00 be 0a 00 0b 33 49 b9 c7 97 70 00 00 dc 01 00 1f d0 c2 43 } 		$a_01_1 = {51 00 54 00 52 00 61 00 64 00 69 00 6f 00 42 00 75 00 74 00 74 00 6f 00 6e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}