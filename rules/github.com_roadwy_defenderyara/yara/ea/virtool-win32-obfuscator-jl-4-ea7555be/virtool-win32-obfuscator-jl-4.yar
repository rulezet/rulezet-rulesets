rule VirTool_Win32_Obfuscator_JL_4{
	meta:
		description = "VirTool:Win32/Obfuscator.JL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 4b 13 0b 80 90 18 ?? ?? 90 18 8b 88 b5 ec f2 ff 90 18 ?? ?? 90 18 03 88 d5 ef f2 ff 90 18 ?? ?? 90 18 0f b6 c9 90 18 ?? ?? 90 18 83 f9 03 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}