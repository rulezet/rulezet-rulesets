rule Trojan_Win32_LummaC_GTK_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 0d ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 50 33 c0 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}