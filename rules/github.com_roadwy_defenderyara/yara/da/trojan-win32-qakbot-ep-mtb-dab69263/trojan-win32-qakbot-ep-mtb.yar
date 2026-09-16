rule Trojan_Win32_Qakbot_EP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ?? 33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 ?? 03 45 ?? 89 45 ?? 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 ?? 03 5d ?? 2b d8 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}