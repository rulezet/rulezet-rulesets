rule Trojan_Win32_Lokibot_AT_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 [0-10] 83 fb 00 74 ?? [0-10] eb } 		$a_03_1 = {89 e0 83 c4 06 ff 28 e8 ?? ff ff ff c3 } 		$a_03_2 = {0f 6e 0b 0f ef c1 51 [0-10] 0f 7e c1 88 c8 59 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}