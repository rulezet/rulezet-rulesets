rule Trojan_Win32_Qakbot_GO_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {32 c1 2a c1 04 ?? c0 c0 ?? c0 c0 ?? 34 ?? c0 c8 ?? 32 c1 c0 c0 ?? 04 ?? 2a c1 32 c1 32 c1 34 ?? 2c ?? aa 4a 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}