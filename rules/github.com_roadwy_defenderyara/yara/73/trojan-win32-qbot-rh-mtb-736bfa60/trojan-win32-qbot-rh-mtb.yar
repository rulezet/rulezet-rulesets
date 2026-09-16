rule Trojan_Win32_Qbot_RH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}