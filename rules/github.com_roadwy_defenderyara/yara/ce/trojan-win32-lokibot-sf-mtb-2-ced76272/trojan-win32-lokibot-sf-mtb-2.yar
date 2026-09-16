rule Trojan_Win32_Lokibot_SF_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec eb ?? 90 05 05 01 90 8a 45 08 90 05 05 01 90 30 01 90 05 05 01 90 eb ?? 90 05 05 01 90 90 05 05 01 90 8b 4d 0c eb ?? 5d c2 } 		$a_03_1 = {8b 06 03 c3 50 68 ?? 00 00 00 ff 15 ?? ?? ?? ?? ff 06 81 3e ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}