rule VirTool_Win32_Obfuscator_AOP{
	meta:
		description = "VirTool:Win32/Obfuscator.AOP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 83 e9 53 8b 55 e8 03 55 a4 88 0a eb d9 c7 45 fc ee ff 00 00 ff 75 ec 8b 45 e8 89 45 cc ff 55 cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}