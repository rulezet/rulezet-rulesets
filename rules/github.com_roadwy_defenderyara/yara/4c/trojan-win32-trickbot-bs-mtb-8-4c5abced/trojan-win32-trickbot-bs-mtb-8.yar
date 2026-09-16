rule Trojan_Win32_Trickbot_BS_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b fb 2b fa 3b f9 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b f8 dd 45 ?? ff 15 ?? ?? ?? ?? 8b 16 8b 4a ?? 88 04 39 b8 01 00 00 00 03 c3 0f 80 } 		$a_02_1 = {50 68 00 00 f0 3f 6a 00 68 ?? ?? ?? ?? 51 ff 15 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}