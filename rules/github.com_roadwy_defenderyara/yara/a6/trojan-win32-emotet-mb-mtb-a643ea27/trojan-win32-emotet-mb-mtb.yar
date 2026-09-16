rule Trojan_Win32_Emotet_MB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0c b7 03 4c 24 28 51 e8 ?? ?? ?? ?? 83 c4 ?? 3b 44 24 2c 74 1f 83 c6 ?? 3b 74 24 14 72 e1 } 		$a_03_1 = {33 d2 8b c1 f7 f7 8a 5c 0c ?? 0f b6 c3 83 c1 01 0f b6 14 2a 03 d6 03 c2 33 d2 be ?? ?? ?? ?? f7 f6 81 f9 90 1b 01 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 72 c9 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}