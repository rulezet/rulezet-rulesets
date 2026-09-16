rule Trojan_Win32_Qbot_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 } 		$a_03_1 = {03 d8 68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}