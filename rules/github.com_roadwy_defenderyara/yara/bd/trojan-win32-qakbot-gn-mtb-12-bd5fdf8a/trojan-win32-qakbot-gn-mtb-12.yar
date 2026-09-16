rule Trojan_Win32_Qakbot_GN_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2d 00 10 00 00 89 45 ec 83 45 ec 04 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 0b 02 00 00 b8 71 00 00 00 ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? b8 ?? ?? ?? ?? ff 75 ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 65 ec } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}