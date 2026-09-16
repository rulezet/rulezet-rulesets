rule Trojan_Win32_Qbot_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}