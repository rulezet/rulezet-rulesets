rule VirTool_Win32_Obfuscator_JL_3{
	meta:
		description = "VirTool:Win32/Obfuscator.JL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 03 75 90 14 [0-02] b8 ?? ?? ?? ?? [0-02] 90 18 [0-02] 8b 88 ?? ?? ?? ?? [0-02] 90 18 [0-02] 03 88 ?? ?? ?? ?? [0-02] 90 18 [0-02] 0f b6 c9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}