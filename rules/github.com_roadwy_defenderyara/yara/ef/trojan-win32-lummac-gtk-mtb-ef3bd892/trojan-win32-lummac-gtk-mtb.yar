rule Trojan_Win32_LummaC_GTK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca 83 f2 ?? 83 e1 37 01 c9 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}