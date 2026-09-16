rule Trojan_Win32_Qbot_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 39 00 00 00 85 c9 0f 85 } 		$a_02_1 = {68 03 5f 00 00 ff 15 ?? ?? ?? ?? 05 c2 5a 00 00 8b 4d ?? 8b 11 2b d0 8b 45 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}