rule Trojan_Win32_StealC_GTM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 83 c4 ?? 68 ?? ?? ?? ?? 8a 0c 02 8b 55 ?? 32 0c 1a 88 0b } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}