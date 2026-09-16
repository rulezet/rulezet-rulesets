rule Trojan_Win32_Bunitu_DSK_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b ca 8b d2 ff 35 ?? ?? ?? ?? 8b d2 8f 45 fc 8b d2 31 4d fc 8b d2 8b 45 fc 8b d2 8b c8 8b d2 b8 00 00 00 00 03 c1 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}