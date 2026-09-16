rule TrojanDropper_Win32_AceLog_B_dha{
	meta:
		description = "TrojanDropper:Win32/AceLog.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 4d 5a 00 00 83 c4 04 66 39 07 74 ?? 68 c1 00 00 00 ff 15 [0-30] 8b 47 3c 81 3c 07 50 45 00 00 75 ?? 8b 47 1c 8b b5 ?? ?? ?? ?? 8b 4f 20 2b f0 85 c9 74 04 8b f1 2b f0 53 56 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4f 1c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}