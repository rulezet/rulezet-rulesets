rule Trojan_Win32_LummaC_GTK_MTB_3{
	meta:
		description = "Trojan:Win32/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 5b 00 00 2b c1 33 d0 0f af 95 } 		$a_03_1 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ?? 50 6a 00 ff 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? d0 f9 82 20 83 bd } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}