rule Trojan_Win32_Zbot_RC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 0b 42 51 00 8b 0d ?? ?? ?? ?? bb ?? ?? ?? ?? 30 03 43 49 85 c9 75 f8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}