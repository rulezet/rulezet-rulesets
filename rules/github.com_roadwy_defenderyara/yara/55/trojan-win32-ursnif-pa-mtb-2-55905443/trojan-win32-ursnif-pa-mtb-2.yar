rule Trojan_Win32_Ursnif_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 03 f6 2b f2 05 74 b3 b8 01 8b 54 24 18 81 c6 ?? ?? ?? ?? 83 44 24 ?? 04 03 f1 89 44 24 14 a3 ?? ?? ?? ?? 89 02 8b c6 2b 05 ?? ?? ?? ?? 83 c0 06 ff 4c 24 ?? 0f b7 d0 89 54 24 ?? 0f 85 } 		$a_00_1 = {8b 44 24 18 8b 00 89 44 24 14 0f b7 c2 89 44 24 10 8b c6 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}