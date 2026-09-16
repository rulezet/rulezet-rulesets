rule Trojan_Win32_Hancitor_GA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 cb 80 e9 ?? 66 0f b6 c1 66 03 c6 66 05 ?? ?? 0f b7 d8 8b 07 05 ?? ?? ?? ?? 89 07 a3 ?? ?? ?? ?? b2 ?? 8a c3 f6 ea 8a 15 ?? ?? ?? ?? f6 da 2a d0 02 ca 83 c7 04 83 6c 24 ?? 01 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}