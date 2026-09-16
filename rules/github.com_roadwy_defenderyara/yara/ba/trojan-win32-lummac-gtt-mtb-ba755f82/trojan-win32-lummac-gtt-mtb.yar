rule Trojan_Win32_LummaC_GTT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 d6 09 ca f7 d2 09 f2 89 d6 81 f6 ?? ?? ?? ?? 83 e2 ?? 01 d2 29 f2 88 10 40 49 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}