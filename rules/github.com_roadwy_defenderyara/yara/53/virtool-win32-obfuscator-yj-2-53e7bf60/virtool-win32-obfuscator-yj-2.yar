rule VirTool_Win32_Obfuscator_YJ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.YJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b7 01 eb 02 b7 00 89 c6 b3 00 80 f9 47 74 3f b3 01 80 f9 45 74 38 b3 02 80 f9 46 74 12 b3 03 80 f9 4e 74 0b 80 f9 4d 0f 85 ?? ?? ?? ?? b3 04 b8 12 00 00 00 8b 55 dc 39 c2 76 25 ba 02 00 00 00 80 f9 4d 75 1b } 		$a_03_1 = {8b 10 85 d2 74 38 8b 4a f8 49 74 32 53 89 c3 8b 42 fc e8 ?? ?? ?? ?? 89 c2 8b 03 89 13 50 8b 48 fc e8 ?? ?? ?? ?? 58 8b 48 f8 49 7c 0e f0 ff 48 f8 75 08 8d 40 f8 e8 ?? ?? ?? ?? 8b 13 5b 89 d0 c3 } 		$a_03_2 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 e0 46 4f 75 d7 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d0 33 c0 5a 59 59 64 89 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}