rule Trojan_Win32_Zbot_BAD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d f8 8b 55 14 8b 45 0c 03 02 8b 4d f8 8b 94 08 ?? ?? ?? ?? 03 55 10 8b 45 14 8b 4d 0c 03 08 8b 45 f8 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}