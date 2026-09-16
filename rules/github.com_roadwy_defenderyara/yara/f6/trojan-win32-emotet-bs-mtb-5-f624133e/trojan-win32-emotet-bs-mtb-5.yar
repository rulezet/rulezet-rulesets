rule Trojan_Win32_Emotet_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b f0 89 44 24 ?? 89 74 24 ?? 89 4c 24 ?? b3 06 eb 08 8b 54 24 ?? 8b 7c 24 ?? 8d 42 01 b9 ?? ?? ?? ?? 99 f7 f9 33 c0 8a 04 2a 03 c7 89 54 24 ?? 8d 34 2a 99 f7 f9 } 		$a_02_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 04 32 8b 54 24 10 0f be 3c 17 e8 ?? ?? ?? ?? 8b 4c 24 10 88 01 41 83 6c 24 14 01 89 4c 24 10 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}