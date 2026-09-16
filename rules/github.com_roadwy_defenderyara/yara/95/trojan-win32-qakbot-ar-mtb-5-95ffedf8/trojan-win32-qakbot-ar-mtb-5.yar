rule Trojan_Win32_Qakbot_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10 } 		$a_00_1 = {03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d } 	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}