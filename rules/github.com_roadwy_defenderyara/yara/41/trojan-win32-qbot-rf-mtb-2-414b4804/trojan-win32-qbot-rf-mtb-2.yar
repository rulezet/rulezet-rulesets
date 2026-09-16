rule Trojan_Win32_Qbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 03 45 b0 03 45 bc 8b 15 ?? ?? ?? ?? 31 02 68 ?? ?? ?? ?? e8 [0-64] 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}