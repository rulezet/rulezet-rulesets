rule Trojan_WinNT_Sirefef_I{
	meta:
		description = "Trojan:WinNT/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0b ff 15 ?? ?? ?? ?? 8b f8 85 ff 7c 10 ff 75 0c 8d 46 04 ff 75 08 e8 ?? ?? ?? ?? 8b d8 6a 00 } 		$a_01_1 = {b9 ff ff 00 00 66 89 4e 38 8b 4f 24 89 4e 24 8b 4f 28 89 4e 28 8b 4f 2c 89 4e 2c 8b 4f 30 89 4e 30 0f b7 4f 2c 8b 57 28 2b d1 0f b7 4f 24 83 c4 0c ff 75 0c 03 d1 89 56 30 ff 75 08 ff d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}