rule TrojanSpy_Win32_Banker_VCE{
	meta:
		description = "TrojanSpy:Win32/Banker.VCE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 2e 76 62 73 } 		$a_01_1 = {66 62 50 72 6f 66 69 6c 65 42 72 6f 77 73 65 72 } 		$a_03_2 = {85 c0 76 1e 68 01 00 11 00 6a 1b 68 00 01 00 00 68 ?? ?? ?? ?? 6a 00 e8 } 		$a_03_3 = {0f 8e dd 00 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ff 8b 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 0f 84 aa 00 00 00 8d 45 f0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}