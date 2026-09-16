rule Trojan_Win32_Emotet_BS_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 84 24 ?? ?? ?? ?? 8a 54 14 20 30 14 01 41 89 4c 24 1c 8b 8c 24 ?? ?? ?? ?? 85 c9 0f 85 } 		$a_02_1 = {03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85 } 		$a_02_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 44 24 20 83 c1 01 89 4c 24 1c 8a 54 14 24 30 54 08 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85 } 		$a_02_3 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 24 8a 4c 14 28 30 08 ff 44 24 1c 39 b4 24 ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}