rule Trojan_Win32_Trickbot_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 55 02 00 00 f7 f9 8b 44 24 ?? 40 83 c4 38 89 44 24 ?? 0f b6 54 14 ?? 30 50 ff 83 bc 24 84 02 00 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}