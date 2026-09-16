rule Trojan_Win32_Zbot_RA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d9 2b df 2b d8 8b 44 24 14 8b 00 81 eb 87 28 00 00 8b fb 8b 5c 24 1c 03 d9 8d 9c 2b ?? ?? ?? ?? 89 1d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}