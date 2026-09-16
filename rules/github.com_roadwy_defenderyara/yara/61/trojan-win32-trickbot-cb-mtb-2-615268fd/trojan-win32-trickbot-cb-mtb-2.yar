rule Trojan_Win32_TrickBot_CB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 0a 84 c9 74 ?? 56 8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 72 ?? 81 e1 ff 00 00 00 83 e9 20 eb ?? 81 e1 ff 00 00 00 03 c1 8a 4a 01 42 84 c9 75 } 		$a_02_1 = {6a 00 ff 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 03 80 00 00 c7 05 ?? ?? ?? ?? 01 68 00 00 c7 05 ?? ?? ?? ?? 01 00 00 00 c7 05 ?? ?? ?? ?? 40 00 00 00 c7 05 ?? ?? ?? ?? 00 10 00 00 e8 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}