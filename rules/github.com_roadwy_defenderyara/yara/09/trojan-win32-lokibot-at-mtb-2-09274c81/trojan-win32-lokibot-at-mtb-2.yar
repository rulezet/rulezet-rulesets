rule Trojan_Win32_Lokibot_AT_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 0f b6 74 1d ff 8b c6 83 c0 df 83 e8 5e 73 1e 8b 04 24 e8 ?? ?? ?? ?? 8d 44 18 ff 50 8d 46 0e b9 5e 00 00 00 99 f7 f9 83 c2 21 58 88 10 43 4f 75 cf 5a 5d 5f 5e 5b c3 } 		$a_03_1 = {6a 00 8b 44 24 1c 8b 40 24 e8 ?? ?? ?? ?? 50 8b 44 24 20 8b 40 08 50 8b 44 24 24 8b 40 0c 03 44 24 20 50 e8 ?? ?? ?? ?? 8b 44 24 18 83 c0 28 89 44 24 18 4b 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}