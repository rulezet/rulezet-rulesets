rule VirTool_Win32_Obfuscator_HP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.HP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 7f 5d 89 7d 08 4e b9 03 6c 80 00 8d 3c 24 2b ca 01 f8 81 f3 ?? ?? ?? ?? 8b 1c 24 4f db e2 9b be ?? ?? ?? ?? 03 df 0f 01 e0 03 c0 3d 16 c6 00 00 72 08 8b 7d 08 ff d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}