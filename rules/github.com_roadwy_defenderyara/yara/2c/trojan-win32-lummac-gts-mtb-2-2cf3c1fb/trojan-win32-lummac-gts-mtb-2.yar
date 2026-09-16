rule Trojan_Win32_LummaC_GTS_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca f7 d2 83 e2 ?? 81 e1 ?? ?? ?? ?? 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}