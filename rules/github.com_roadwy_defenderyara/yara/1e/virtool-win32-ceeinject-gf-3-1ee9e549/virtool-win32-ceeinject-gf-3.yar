rule VirTool_Win32_CeeInject_GF_3{
	meta:
		description = "VirTool:Win32/CeeInject.GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c2 21 89 95 fc fe ff ff 6a 40 68 00 10 00 00 8b 85 00 ff ff ff 50 6a 00 ff 15 9c e0 40 00 a3 ?? ?? ?? 00 0f b7 8d 6c fd ff ff 83 c1 60 0f b6 95 f3 fe ff ff 33 ca } 		$a_03_1 = {c7 85 fc fe ff ff 57 00 00 00 8b 95 e8 fe ff ff 2b 95 48 fe ff ff 83 ea 26 66 89 95 34 fe ff ff a1 ?? ?? ?? ?? 50 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}