rule VirTool_Win32_VBInject_AEU_2{
	meta:
		description = "VirTool:Win32/VBInject.AEU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 05 00 00 00 c7 85 5c ff ff ff 38 d5 03 00 c7 85 60 ff ff ff 01 00 00 00 c7 45 c4 00 00 00 00 eb 12 8b 45 c4 03 85 60 ff ff ff 0f 80 d2 03 00 00 89 45 c4 8b 4d c4 3b 8d 5c ff ff ff 0f 8f 20 01 00 00 } 		$a_01_1 = {c7 04 ca 8c 63 23 82 c7 44 ca 04 65 16 a4 ba 8b 58 14 8b 50 0c b9 ea 01 00 00 2b cb c7 04 ca 0d 2b 4b ee c7 44 ca 04 39 21 57 e7 } 		$a_01_2 = {c7 04 d7 f6 c2 d4 3d c7 44 d7 04 fe a0 4c b9 8b 58 14 8b 78 0c ba 7e 01 00 00 2b d3 c7 04 d7 37 4b 5d 4f c7 44 d7 04 f6 3c 31 77 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}