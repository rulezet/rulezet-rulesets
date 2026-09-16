rule Trojan_Win32_Lokibot_D_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff ff 5a 5f 5e 5b c3 90 0a 4f 00 b0 ?? 8b d3 8b fe 03 fa 8b 15 ?? ?? ?? ?? 8a 92 ?? ?? ?? ?? 32 d0 88 17 83 05 ?? ?? ?? ?? 02 43 81 fb ?? ?? 00 00 75 d8 8b c6 e8 ?? ?? ff ff 5a 5f 5e 5b c3 } 		$a_02_1 = {8b f0 54 6a 40 68 83 5b 00 00 56 e8 ?? ?? ?? ?? 33 c0 a3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}