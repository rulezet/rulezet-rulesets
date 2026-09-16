rule VirTool_Win32_Obfuscator_AQT_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AQT,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 3c 08 0f af fe 8d 0c 12 8b df 2b d9 0f af da 03 d8 8a c3 32 85 cf e9 ff ff } 		$a_01_1 = {8a 85 1c ea ff ff 8b 8d 0c ea ff ff 8b 95 04 ea ff ff 88 04 11 eb 0f 8b 85 0c ea ff ff 8b 8d 04 ea ff ff 88 04 08 } 		$a_01_2 = {8b 85 18 ea ff ff 8d 34 02 0f af b5 d4 e9 ff ff 0f af f7 0f af f0 8b 85 04 ea ff ff 8d 0c 9b 03 f1 43 0f af de 40 3b 85 c0 e9 ff ff 89 9d f4 e9 ff ff 89 85 04 ea ff ff 0f 8c 17 fe ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}