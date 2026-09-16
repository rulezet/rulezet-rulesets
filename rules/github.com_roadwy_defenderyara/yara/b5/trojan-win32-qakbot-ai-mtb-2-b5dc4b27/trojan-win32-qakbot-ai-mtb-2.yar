rule Trojan_Win32_Qakbot_AI_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 66 3b e4 74 ?? c6 45 ?? 72 66 3b db 74 ?? c6 45 ?? 65 66 3b ed 74 ?? c6 45 ?? 53 66 3b f6 74 ?? c6 45 ?? 76 eb ?? c6 45 ?? 72 66 3b d2 74 ?? c6 45 ?? 73 3a e4 74 ?? c6 45 ?? 65 3a d2 74 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}