rule TrojanSpy_Win32_Gauss_plugin_G{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 49 00 73 00 76 00 70 00 34 00 30 00 30 00 33 00 6c 00 74 00 72 00 45 00 76 00 65 00 6e 00 74 00 00 00 } 		$a_03_1 = {89 7d fc 50 8d 45 fc 68 86 0b 00 00 50 6a 65 57 89 7d ?? 89 7d ?? 89 7d ?? e8 07 0e 00 00 3b c7 74 0b 3d ea 00 00 00 0f 85 ?? ?? ?? ?? 6a 66 e8 ?? ?? ?? ?? 39 7d } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}