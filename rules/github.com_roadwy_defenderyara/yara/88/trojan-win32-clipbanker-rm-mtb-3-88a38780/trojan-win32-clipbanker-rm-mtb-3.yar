rule Trojan_Win32_ClipBanker_RM_MTB_3{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f6 b1 81 29 75 8b 4c 24 ?? 89 4c 24 ?? 39 f0 75 ?? 66 b8 50 d4 66 8b 4c 24 ?? 8b 54 24 ?? 89 54 24 ?? 66 39 c8 76 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}