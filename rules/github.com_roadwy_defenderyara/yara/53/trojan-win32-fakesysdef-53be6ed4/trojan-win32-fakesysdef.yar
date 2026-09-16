rule Trojan_Win32_FakeSysdef{
	meta:
		description = "Trojan:Win32/FakeSysdef,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ca 8b 55 08 03 55 fc 88 0a 0f be 45 fb 05 23 cb 12 00 0f af 45 f0 89 45 f0 8b 4d 08 03 4d fc 8b 55 08 03 55 fc 8a 02 88 41 ff eb b0 } 		$a_03_1 = {8b 95 d8 fe ff ff 52 8b 45 f0 50 68 ?? ?? ?? ?? ff 15 ?? ?? 40 00 5e 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}