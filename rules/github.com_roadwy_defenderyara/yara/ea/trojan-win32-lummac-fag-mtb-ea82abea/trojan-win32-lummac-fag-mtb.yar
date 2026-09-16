rule Trojan_Win32_LummaC_FAG_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 0c 16 30 d9 88 0c 16 42 39 94 24 ?? ?? ?? ?? 89 f9 0f 84 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}