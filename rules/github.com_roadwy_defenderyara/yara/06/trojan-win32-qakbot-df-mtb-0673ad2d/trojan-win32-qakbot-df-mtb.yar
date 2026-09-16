rule Trojan_Win32_Qakbot_DF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ca 2b 0d ?? ?? ?? ?? 81 c1 5c 45 01 00 0f b6 d2 89 0d ?? ?? ?? ?? 0f b6 cb 0f af d1 02 54 24 10 89 54 24 14 88 15 ?? ?? ?? ?? 8d 56 ff 8b 74 24 18 8b 0e 81 c1 70 36 08 01 89 0e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}