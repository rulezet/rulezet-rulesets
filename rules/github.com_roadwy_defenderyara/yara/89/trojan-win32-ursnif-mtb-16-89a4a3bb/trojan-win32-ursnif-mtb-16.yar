rule Trojan_Win32_Ursnif_MTB_16{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c9 8d 5f 04 03 de 89 1d ?? ?? ?? ?? 8d 04 11 83 f8 ?? 75 07 [0-10] 2b dd 2b f7 83 c3 ?? 83 c6 ?? 0f b7 ce 81 c5 ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? 8b c1 8b 5c 24 10 03 e8 8b 13 81 ff ?? ?? ?? ?? 75 } 		$a_02_1 = {0f b7 f1 81 c1 ?? ?? ?? ?? 2b f7 89 13 83 c6 ?? 83 c3 ?? 03 c6 89 5c 24 10 03 c8 ff 4c 24 14 0f 85 ?? ?? ff ff } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}