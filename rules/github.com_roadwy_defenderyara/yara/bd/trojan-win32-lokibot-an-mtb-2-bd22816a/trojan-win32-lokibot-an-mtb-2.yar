rule Trojan_Win32_Lokibot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 ?? 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 f8 33 c0 89 45 f4 ba ?? ?? ?? ?? 8a 02 88 45 ff b0 ?? 8a 5d ff 32 c3 8b 7d f8 03 7d f4 88 07 ff 45 f4 42 81 7d f4 ?? ?? 00 00 75 df ?? 00 00 00 00 [0-04] 00 00 03 ?? f8 ff ?? 8b e5 5d c2 04 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}