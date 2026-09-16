rule VirTool_Win32_Obfuscator_APM_2{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 16 8d 45 9c [0-18] eb d9 8b ?? 9c ff 90 17 02 02 01 65 9c e2 c7 45 c8 00 00 00 00 8b 4d fc 51 e8 ?? ?? ff ff 5f 5e 5b 8b e5 5d c2 04 00 55 8b ec a1 ?? ?? 40 00 5d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}