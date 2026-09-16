rule Trojan_Win32_AnchorLoader_A_ibt{
	meta:
		description = "Trojan:Win32/AnchorLoader.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 61 33 c0 89 45 f6 66 89 ?? ?? 58 6a 6e 66 89 ?? ?? 58 6a 63 66 89 ?? ?? 58 6a 68 66 89 ?? ?? 58 6a 6f 66 89 ?? ?? 58 6a 72 66 89 ?? ?? 58 66 89 ?? ?? 33 c0 66 89 ?? ?? 8d 45 e8 } 		$a_80_1 = {41 6e 63 68 6f 72 5f 78 38 36 2e 65 78 65 } 		$a_80_2 = {52 65 6c 65 61 73 65 5c 41 6e 63 68 6f 72 5f 78 38 36 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}