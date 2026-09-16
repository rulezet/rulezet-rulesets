rule VirTool_Win32_Obfuscator_ADX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ADX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ac 8b da c1 eb 18 32 c3 aa eb 0a 8b fd 03 f9 8b f7 ac 32 c1 aa 41 81 f9 ?? ?? ?? 00 72 02 } 		$a_03_1 = {8b d6 8b fd 03 f9 8b f7 ac 8b da c1 eb 18 32 c3 aa 41 81 ?? ?? ?? ?? 00 72 02 ff e5 } 		$a_03_2 = {8b fb f3 a5 2d ?? 07 00 00 2c ?? 33 c9 66 a5 d0 e0 30 04 19 41 83 f9 ?? 7c f7 90 09 0a 00 b9 ?? 00 00 00 be } 		$a_01_3 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 72 d9 5f 5b 0f b7 40 02 33 c9 66 89 0c 46 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}