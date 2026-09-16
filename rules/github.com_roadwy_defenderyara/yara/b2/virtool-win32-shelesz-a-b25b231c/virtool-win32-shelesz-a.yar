rule VirTool_Win32_Shelesz_A{
	meta:
		description = "VirTool:Win32/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {52 51 68 00 08 00 00 ff 75 c0 ?? ?? ?? ?? ?? ?? 85 f6 ?? ?? 2b fe 81 ff 00 10 00 00 ?? ?? 8b 4e fc 83 c7 23 2b f1 ?? ?? ?? 83 f8 1f } 		$a_01_1 = {8b 45 d0 8b 4d d0 83 c1 76 33 4c 85 cc 8b 45 d0 89 4c 85 cc 8b 45 d0 40 89 45 d0 83 7d d0 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}