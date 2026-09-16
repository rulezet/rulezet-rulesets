rule Trojan_Win32_ICLoader_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/ICLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {d7 7b 0b 2a 01 00 00 00 99 60 49 00 b5 cb 45 00 00 ae 0a 00 23 97 28 5f 6c 90 45 00 00 d4 00 00 d8 96 a9 71 } 		$a_01_1 = {7b 4b 49 00 97 b6 45 00 00 ae 0a 00 23 97 28 5f 3b 7b 45 00 00 d4 00 00 4d c2 0b 88 } 		$a_01_2 = {42 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 54 00 56 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}