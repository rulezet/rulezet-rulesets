rule Trojan_Win32_Qakbot_RM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 18 89 05 ?? ?? ?? ?? b8 26 00 00 00 03 05 ?? ?? ?? ?? 83 e8 4f 33 05 ?? ?? ?? ?? 03 c0 81 e8 36 52 e0 7d 03 c0 83 e8 1f 33 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}