rule Trojan_Win32_Lokibot_SH_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 e4 53 56 57 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 e8 ?? ?? ?? ?? 89 45 fc [0-10] 8b 45 fc 89 45 f8 [0-10] 8d 45 e8 50 e8 [0-10] 8b 45 f8 3b 45 fc 0f } 		$a_03_1 = {8b c8 b2 9c 8b c3 e8 ?? ?? ff ff 90 05 0a 01 90 46 81 fe ?? ?? 00 00 75 } 		$a_03_2 = {8d 55 e8 8d 45 f0 e8 ?? ?? ff ff 8b c8 } 		$a_81_3 = {52 65 73 6f 6c 76 69 6e 67 20 68 6f 73 74 6e 61 6d 65 20 25 73 } 		$a_81_4 = {44 69 73 63 6f 6e 6e 65 63 74 69 6e 67 20 66 72 6f 6d 20 25 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}