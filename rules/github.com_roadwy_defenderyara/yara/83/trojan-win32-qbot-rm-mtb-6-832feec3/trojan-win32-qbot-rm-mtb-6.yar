rule Trojan_Win32_Qbot_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}