rule Trojan_Win32_Qbot_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 49 0e 00 00 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 8b 00 8b 55 ?? 03 55 ?? 03 55 ?? 33 c2 03 d8 68 49 0e 00 00 6a } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}