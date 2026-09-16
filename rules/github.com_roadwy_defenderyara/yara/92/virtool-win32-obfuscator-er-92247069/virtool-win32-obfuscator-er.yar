rule VirTool_Win32_Obfuscator_ER{
	meta:
		description = "VirTool:Win32/Obfuscator.ER,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 04 00 00 00 83 eb 02 ba 15 12 40 00 f7 d3 f7 db 81 fc 54 45 02 00 30 1a 83 ea 05 90 83 c2 06 81 fa 15 1a 41 00 75 e5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}