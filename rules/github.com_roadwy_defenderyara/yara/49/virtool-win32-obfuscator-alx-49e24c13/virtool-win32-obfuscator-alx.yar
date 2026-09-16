rule VirTool_Win32_Obfuscator_ALX_{
	meta:
		description = "VirTool:Win32/Obfuscator.ALX!!ObfuscatorAlx.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 0c 00 00 "
		
	strings :
		$a_01_0 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db } 		$a_01_1 = {8b 42 08 89 45 e0 8b 4d f0 8b 51 0c 89 55 e8 ff 75 e8 ff 75 e0 ff 75 dc ff 75 e4 8b 45 fc ff d0 } 		$a_01_2 = {e8 00 00 00 00 58 83 c0 05 c3 } 		$a_01_3 = {e8 05 fe ff ff 89 45 f8 8b 45 f8 8b 48 0c 89 4d f4 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc } 		$a_01_4 = {89 51 1c 68 d8 26 fe 52 } 		$a_01_5 = {c6 45 f6 90 c6 45 f7 8b c6 45 f8 ff c6 45 f9 55 6a 06 8d 45 f4 } 		$a_01_6 = {b6 08 66 d1 eb 66 d1 d8 73 09 66 35 20 83 66 81 f3 b8 ed fe ce 75 eb } 		$a_01_7 = {ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a } 		$a_01_8 = {c6 45 dc 6e c6 45 dd 74 c6 45 de 64 c6 45 df 6c c6 45 e0 6c c6 45 e1 00 8d 45 dc 50 e8 } 		$a_01_9 = {89 51 04 68 23 f9 35 9d } 		$a_01_10 = {89 51 44 68 d7 70 a4 37 } 		$a_01_11 = {89 51 10 68 af b6 1a 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=2
 
}