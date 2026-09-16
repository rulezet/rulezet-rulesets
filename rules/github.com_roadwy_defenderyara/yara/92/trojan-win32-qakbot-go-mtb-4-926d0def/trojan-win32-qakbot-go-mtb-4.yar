rule Trojan_Win32_Qakbot_GO_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 90 08 40 01 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}