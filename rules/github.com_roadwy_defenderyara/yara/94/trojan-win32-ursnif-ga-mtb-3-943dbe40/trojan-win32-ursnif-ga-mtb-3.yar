rule Trojan_Win32_Ursnif_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 f0 2b de 8b 37 03 eb b3 59 f6 eb 8a da 2a d8 81 3d [0-08] 88 1d [0-04] 90 18 8b 1d [0-04] 81 c6 [0-04] 8a ca 2a cb 89 37 80 c1 ?? 83 c7 ?? 83 6c 24 ?? 01 89 35 [0-04] 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}