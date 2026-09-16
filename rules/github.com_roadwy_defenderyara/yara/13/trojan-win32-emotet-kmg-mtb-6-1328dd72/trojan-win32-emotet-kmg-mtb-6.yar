rule Trojan_Win32_Emotet_KMG_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a c8 88 44 24 ?? 03 cb 81 e1 ff 00 00 00 8b d9 8a 54 1c ?? 88 54 3c ?? 88 44 1c } 		$a_02_1 = {8a c8 88 44 24 ?? 03 cf 81 e1 ff 00 00 00 8b f9 8a 54 3c ?? 88 54 34 ?? 88 44 3c ?? e8 } 		$a_02_2 = {32 c2 88 45 00 8b 44 24 ?? 45 48 89 44 24 ?? 0f 85 } 		$a_02_3 = {40 8a 54 04 ?? 8a 03 32 c2 88 03 43 4d 0f 85 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}