rule VirTool_Win32_Obfuscator_HP{
	meta:
		description = "VirTool:Win32/Obfuscator.HP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f 01 e0 03 c0 3d ?? ?? ?? ?? 72 ?? 8d } 		$a_02_1 = {a1 6c 02 fe 7f [0-06] 3c 06 74 ?? ba } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}