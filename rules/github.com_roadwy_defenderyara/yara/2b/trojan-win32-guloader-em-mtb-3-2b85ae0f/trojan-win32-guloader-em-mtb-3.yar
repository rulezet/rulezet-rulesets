rule Trojan_Win32_GuLoader_EM_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 e3 de d1 00 00 5b 81 ea 19 f5 00 00 41 35 82 18 00 00 43 81 f9 c2 b4 00 00 74 14 48 f7 d2 81 ea 13 54 01 00 b9 f8 7e 01 00 81 e2 10 03 00 00 05 c9 0d } 		$a_01_1 = {8b 47 3c 33 f6 8b 44 38 78 03 c7 8b 48 24 8b 50 20 03 cf 89 4d f8 03 d7 8b 48 1c 03 cf 89 55 fc 89 4d f4 8b 48 18 89 4d 08 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}