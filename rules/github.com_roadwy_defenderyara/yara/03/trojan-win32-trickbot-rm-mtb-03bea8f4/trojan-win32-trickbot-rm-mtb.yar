rule Trojan_Win32_Trickbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fb 8b 75 ?? 8b c1 8a 1c 31 80 c2 4f 32 da 47 88 1c 31 b9 05 00 00 00 99 f7 f9 89 7d ?? 85 d2 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}