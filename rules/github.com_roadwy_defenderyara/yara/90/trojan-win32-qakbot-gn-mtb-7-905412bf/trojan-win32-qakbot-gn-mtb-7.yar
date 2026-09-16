rule Trojan_Win32_Qakbot_GN_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff ?? ?? ?? ?? ?? b8 dd 09 00 00 ff ?? ?? ?? ?? ?? b8 16 02 00 00 ff ?? ?? ?? ?? ?? b8 ?? 02 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? b8 01 00 00 00 50 ff } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}