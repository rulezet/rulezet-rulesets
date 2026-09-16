rule VirTool_Win32_Injector_FZ{
	meta:
		description = "VirTool:Win32/Injector.FZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 08 83 45 ?? 01 83 45 ?? 01 81 7d ?? ?? ?? 01 00 7e ef } 		$a_01_1 = {00 53 63 75 6c 6b 73 00 53 63 75 6c 6b 73 40 32 38 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}