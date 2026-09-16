rule VirTool_Win32_CeeInject_GL{
	meta:
		description = "VirTool:Win32/CeeInject.GL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 00 00 99 b9 ?? ?? 00 00 f7 f9 33 d2 8a 90 90 ?? ?? ?? 00 8b ca 83 f1 ?? 33 d2 8a 15 ?? ?? ?? 00 33 ca 83 f1 90 09 06 00 8b 45 ?? 69 } 		$a_03_1 = {00 df e0 f6 c4 41 75 ?? 68 00 dc ab 40 6a 00 90 90 90 90 e9 90 09 08 00 db 45 ?? dc 1d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}