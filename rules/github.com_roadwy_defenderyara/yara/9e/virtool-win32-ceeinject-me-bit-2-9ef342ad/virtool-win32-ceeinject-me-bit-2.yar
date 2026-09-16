rule VirTool_Win32_CeeInject_ME_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.ME!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 11 33 95 ?? fe ff ff 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 88 10 } 		$a_03_1 = {0f b7 48 06 39 4d ?? 0f 8d ?? ?? 00 00 8b 55 ?? 8b 45 ?? 03 42 3c 8b 4d ?? 6b c9 ?? 8d 94 08 ?? 00 00 00 } 		$a_03_2 = {6a 00 8b 55 ?? 8b 42 ?? 50 8b 4d ?? 8b 55 ?? 03 51 ?? 52 8b 45 ?? 8b 4d ?? 03 48 ?? 51 8b 55 ?? 52 a1 ?? ?? ?? 00 ff d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}