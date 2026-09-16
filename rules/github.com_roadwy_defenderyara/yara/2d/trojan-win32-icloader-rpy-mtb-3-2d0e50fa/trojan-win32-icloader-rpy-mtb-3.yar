rule Trojan_Win32_ICLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {14 64 74 00 8b c8 70 00 00 be 0a 00 0b 33 49 b9 78 81 70 00 00 dc 01 00 6a 8d 5e 14 } 		$a_01_1 = {ba 73 74 00 31 d8 70 00 00 be 0a 00 0b 33 49 b9 10 91 70 00 00 dc 01 00 80 f1 86 03 } 		$a_01_2 = {44 00 54 00 50 00 61 00 6e 00 65 00 6c 00 51 00 54 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}