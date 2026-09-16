rule Trojan_Win32_Emotet_P_3{
	meta:
		description = "Trojan:Win32/Emotet.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 2c 89 44 24 20 89 4c 24 1c 89 54 24 18 89 5c 24 14 89 7c 24 10 89 74 24 0c 8b 44 24 0c 8b 0c 85 ?? ?? ?? ?? 8b 54 24 24 39 d1 89 44 24 08 89 4c 24 04 73 6d 8b 44 24 04 b9 3e 00 00 00 8b 54 24 14 81 e2 ?? ?? ?? ?? 89 54 24 28 c7 44 24 2c 00 00 00 00 89 04 24 31 d2 f7 f1 8b 4c 24 1c 8b 34 24 8a 1c 31 8b 7c 24 24 } 		$a_02_1 = {83 f7 ff 8a 7c 24 3b 80 c7 82 89 7c 24 34 8a 0c 15 ?? ?? ?? ?? 00 fb 28 cb 8b 54 24 18 88 1c 32 83 c6 3e 8b 7c 24 24 39 fe 89 74 24 04 72 9d eb 08 8d 65 f4 5f 5b 5e 5d c3 8b 44 24 08 83 c0 01 83 f8 3e 89 44 24 0c 74 e8 e9 63 ff ff ff } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}