rule Trojan_Win32_Lokibot_SN_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 fb [0-04] 8a 45 fb 32 45 fa 8b 55 fc 88 02 ff 45 f4 81 7d f4 } 		$a_03_1 = {c7 45 e0 01 00 00 00 6a 00 6a 00 e8 ?? ?? ?? ?? ff 45 e0 81 7d e0 ?? ?? ?? ?? 75 ?? 89 ff 89 ff 89 ff e8 ?? ?? ?? ?? 89 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}