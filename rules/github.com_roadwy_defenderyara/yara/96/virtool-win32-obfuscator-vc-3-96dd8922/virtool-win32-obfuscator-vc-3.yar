rule VirTool_Win32_Obfuscator_VC_3{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d0 4a 75 83 50 58 60 8b } 		$a_01_1 = {fe c0 f6 d8 04 9d fe c0 d0 c8 fc 90 aa 49 0f } 		$a_01_2 = {ac 8b d2 fc 09 c0 d0 c8 f6 d8 34 e1 fc d0 c0 fe c0 d0 c0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}