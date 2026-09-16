rule Trojan_Win32_Gozi_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c0 80 e9 ?? 83 c0 ?? 89 35 [0-04] 8b 35 [0-04] 03 c2 89 44 24 ?? 83 c6 cb 8b 03 05 [0-04] 89 03 83 c3 04 a3 [0-04] 8b 44 24 ?? 03 c6 83 6c 24 ?? 01 8b 74 24 ?? 0f b7 c0 89 44 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}