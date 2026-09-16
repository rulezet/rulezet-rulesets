rule Trojan_Win32_CryptInject_PF_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 33 d2 8b c7 f7 74 24 20 8b 44 24 14 8a 0c 50 30 0c 1f 47 3b fd 75 95 } 		$a_01_1 = {56 8b 74 24 10 85 f6 76 13 8b 44 24 08 8b 4c 24 0c 2b c8 8a 14 01 88 10 40 4e 75 f7 5e c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}