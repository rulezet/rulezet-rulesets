rule Trojan_Win32_Qbot_AV_MSR_2{
	meta:
		description = "Trojan:Win32/Qbot.AV!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}