rule Trojan_Win32_Qbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 5c 0e 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 15 ?? ?? ?? ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 5c 0e 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 5c 0e 00 00 6a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}