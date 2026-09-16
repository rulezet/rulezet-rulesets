rule Trojan_Win32_Trickbot_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 ?? 8a 18 83 c4 0c 8a 54 14 ?? 32 da 88 18 40 89 44 24 ?? ff 4c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}