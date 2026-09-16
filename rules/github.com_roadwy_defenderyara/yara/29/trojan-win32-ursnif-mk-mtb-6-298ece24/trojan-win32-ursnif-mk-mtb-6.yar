rule Trojan_Win32_Ursnif_MK_MTB_6{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 30 8b 4c 24 20 66 8b 14 48 66 89 d6 66 83 ?? ?? c7 44 24 60 ?? ?? ?? ?? 66 89 d7 66 83 c7 ?? 66 83 fe ?? 66 0f 42 d7 8b 44 24 58 35 ?? ?? ?? ?? 8b 5c 24 0c 89 5c 24 60 8b 74 24 10 66 39 14 4e 0f 94 c3 80 e3 01 88 5c 24 43 8b 74 24 0c 69 f6 ?? ?? ?? ?? 66 83 fa 00 0f 95 c3 8a 7c 24 43 89 74 24 60 8b 74 24 34 01 c1 39 f1 0f 92 c0 20 df 20 c7 89 4c 24 20 f6 c7 01 75 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}