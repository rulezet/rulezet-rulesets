rule Trojan_Win32_ClipBanker_RM_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f3 c4 eb f8 1c 8a 0c 01 89 5c 24 ?? 88 0c 02 69 54 24 ?? 27 e2 d0 4b 89 54 24 ?? 83 c0 01 8b 54 24 ?? 39 d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}