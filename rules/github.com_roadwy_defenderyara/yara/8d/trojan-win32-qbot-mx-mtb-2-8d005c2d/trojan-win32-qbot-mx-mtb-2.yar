rule Trojan_Win32_Qbot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } 		$a_80_1 = {31 36 72 74 75 2e 6c 41 6c 2b 6f 63 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}