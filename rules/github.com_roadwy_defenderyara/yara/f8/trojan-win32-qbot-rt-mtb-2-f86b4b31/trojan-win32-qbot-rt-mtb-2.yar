rule Trojan_Win32_Qbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 ?? 04 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}