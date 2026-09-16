rule Trojan_Win32_StealC_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 41 f7 e5 c1 ea ?? 6b c2 ?? 8d 14 1e 0f b6 44 10 ?? 32 44 1e ?? 88 44 1f ?? 43 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}