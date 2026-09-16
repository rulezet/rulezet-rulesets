rule Trojan_Win32_Qakbot_AJ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 66 3b db 74 ?? c6 45 ?? 65 66 3b ?? 74 ?? c6 45 ?? 73 66 3b ?? 74 ?? c6 45 ?? 74 3a ?? 74 ?? c6 45 ?? 52 66 3b ?? 74 ?? c6 45 ?? 67 66 3b ?? 74 ?? c6 45 ?? 65 66 3b ?? 74 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}