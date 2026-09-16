rule Trojan_Win32_Lokibot_MFP_MTB_3{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 06 00 00 "
		
	strings :
		$a_02_0 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 37 01 00 00 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 83 e9 59 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff } 		$a_02_1 = {ff 95 c0 fd ff ff c7 85 ec fd ff ff ?? ?? ?? ?? eb 0f 8b 85 ec fd ff ff 83 c0 01 89 85 ec fd ff ff 8b 8d ec fd ff ff 3b 8d d8 fd ff ff 0f 83 ee ?? ?? ?? 8b 95 e4 fd ff ff 03 95 ec fd ff ff 8a 02 88 85 f3 fd ff ff 0f b6 8d f3 fd ff ff 03 8d ec fd ff ff 88 8d f3 fd ff ff 0f b6 95 f3 fd ff ff } 		$a_81_2 = {43 6c 6f 73 65 43 6c 69 70 62 6f 61 72 64 } 		$a_81_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } 		$a_81_4 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } 		$a_81_5 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}