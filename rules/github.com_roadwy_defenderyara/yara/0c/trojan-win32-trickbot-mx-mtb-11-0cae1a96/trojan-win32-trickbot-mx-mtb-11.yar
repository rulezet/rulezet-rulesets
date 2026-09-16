rule Trojan_Win32_Trickbot_MX_MTB_11{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0f 83 c3 01 0f 80 ?? ?? ?? ?? 8b 51 0c 88 04 2a 8b 44 24 10 3b d8 } 		$a_02_1 = {6a 40 8b b4 24 4c 01 00 00 56 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 81 e1 ff ff 00 00 81 f9 4d 5a 00 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}