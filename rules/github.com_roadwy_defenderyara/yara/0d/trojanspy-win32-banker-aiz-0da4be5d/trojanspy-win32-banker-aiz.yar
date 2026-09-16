rule TrojanSpy_Win32_Banker_AIZ{
	meta:
		description = "TrojanSpy:Win32/Banker.AIZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 8e 9b 01 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 } 		$a_03_1 = {68 e0 93 04 00 e8 ?? ?? ?? ff 6a 00 8d 95 ?? ?? ?? ff b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 ?? ?? ?? ff e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff e8 ?? ?? ?? ff eb 90 04 01 02 23 32 } 		$a_03_2 = {63 6d 64 20 2f 6b 20 00 ?? ?? ?? ?? ?? ?? [0-03] 43 90 04 01 04 23 25 2a 40 3a 90 04 01 04 23 25 2a 40 5c 90 04 01 04 23 25 2a 40 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}