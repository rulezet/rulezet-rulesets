rule Trojan_Win32_Killfiles_BI{
	meta:
		description = "Trojan:Win32/Killfiles.BI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 95 6c fe ff ff 8b 02 89 85 bc fe ff ff c7 85 f0 fe ff ff ?? ?? 40 00 c7 85 e8 fe ff ff 08 00 00 00 c7 85 00 ff ff ff 02 00 00 00 c7 85 f8 fe ff ff 02 00 00 00 8d 4d 8c 51 b8 10 00 00 00 } 		$a_01_1 = {c7 45 fc 1d 00 00 00 8d 4d cc 89 8d 00 ff ff ff c7 85 f8 fe ff ff 08 40 00 00 6a 00 8d 95 f8 fe ff ff 52 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}