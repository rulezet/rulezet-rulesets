rule Trojan_Win32_Qbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 57 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 57 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 57 15 00 00 6a 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}