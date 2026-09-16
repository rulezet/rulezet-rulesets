rule Trojan_Win32_Qbot_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00 } 		$a_03_1 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 8d 85 ?? ?? ?? ?? 33 c9 ba 3c 00 00 00 e8 ?? ?? ?? ?? 8d 85 68 ff ff ff 33 c9 ba 3c 00 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}