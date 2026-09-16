rule Trojan_Win32_Emotet_F{
	meta:
		description = "Trojan:Win32/Emotet.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8b 4c 24 2c ba ?? ?? ?? ?? 29 ca 31 c9 89 44 24 08 89 54 24 04 89 ca 8b 4c 24 04 f7 f1 8b 44 24 20 8b 4c 24 08 8a 1c 08 8a ba ?? ?? ?? ?? 28 fb c7 44 24 34 ff ff ff ff c7 44 24 30 ?? ?? ?? ?? 8b 54 24 1c 88 1c 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}