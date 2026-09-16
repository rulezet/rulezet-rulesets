rule VirTool_Win32_CryptInject_MTB_4{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 8b 45 08 e8 ?? ?? ?? ?? ff 45 f8 81 7d f8 ?? ?? ?? ?? 75 e7 } 		$a_02_1 = {88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 73 05 e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8a 00 88 45 ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 30 45 f7 8b 45 ?? 8a 55 f7 88 10 8b e5 5d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}