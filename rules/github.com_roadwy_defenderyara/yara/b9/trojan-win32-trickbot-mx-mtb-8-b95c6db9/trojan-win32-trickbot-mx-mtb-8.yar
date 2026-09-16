rule Trojan_Win32_Trickbot_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {52 53 6a 01 53 50 ff 15 ?? ?? ?? ?? 85 c0 5b 0f 95 c0 } 		$a_02_1 = {33 c0 3b f3 7e ?? 8b 4c 24 ?? 8d 4c 31 ?? ?? 8a 11 88 ?? ?? ?? ?? ?? 83 c0 01 83 e9 01 3b c6 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}