rule Trojan_Win32_Emotet_BA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c6 99 be ?? ?? ?? ?? f7 fe 8a 44 8c 04 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 04 89 44 b4 10 33 d2 8d 47 ff f7 f3 0f } 		$a_00_1 = {8a 44 8c 10 8b f2 8b 54 b4 10 89 54 8c 10 0f b6 d0 89 54 b4 10 8b 44 8c 10 03 c2 99 f7 } 		$a_00_2 = {f7 fe 8a 44 8c 08 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 08 89 44 b4 10 33 d2 8b c7 f7 f3 0f } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}