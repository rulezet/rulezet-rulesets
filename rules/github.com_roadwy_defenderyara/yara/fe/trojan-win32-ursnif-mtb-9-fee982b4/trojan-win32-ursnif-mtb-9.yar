rule Trojan_Win32_Ursnif_MTB_9{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 8d 7e ?? 81 c1 ?? ?? ?? ?? 03 fa 89 0d ?? ?? ?? ?? 89 08 a1 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 76 } 		$a_02_1 = {8b 44 24 14 83 44 24 0c 04 0f b7 c8 8d 04 95 00 00 00 00 89 4c 24 10 f7 d9 2b c8 a1 ?? ?? ?? ?? 03 f9 ff 4c 24 18 8b 4c 24 10 0f 85 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}