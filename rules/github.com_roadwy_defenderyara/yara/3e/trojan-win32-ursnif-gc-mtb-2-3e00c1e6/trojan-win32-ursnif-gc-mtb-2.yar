rule Trojan_Win32_Ursnif_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 83 c1 ?? 03 cf 89 0d [0-04] 90 18 8b 7c 24 ?? 81 c3 [0-04] 0f b6 c8 66 2b ca 89 1d [0-04] 89 1f 83 c7 ?? 8b 1d [0-04] 66 03 cb 66 03 4c 24 ?? 66 03 f1 89 7c 24 ?? ff 4c 24 ?? 8b 7c 24 ?? 66 89 74 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}