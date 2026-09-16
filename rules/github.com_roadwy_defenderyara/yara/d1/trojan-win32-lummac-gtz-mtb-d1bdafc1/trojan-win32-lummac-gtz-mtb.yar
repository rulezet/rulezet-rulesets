rule Trojan_Win32_LummaC_GTZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 14 ?? ?? ?? ?? 31 d1 89 4c 24 ?? 8b 4c 24 ?? 80 c1 ?? 88 8c 14 ?? ?? ?? ?? 42 81 fa } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}