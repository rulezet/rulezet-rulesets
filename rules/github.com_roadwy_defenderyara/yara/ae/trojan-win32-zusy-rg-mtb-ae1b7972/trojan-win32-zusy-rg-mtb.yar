rule Trojan_Win32_Zusy_RG_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 0f 43 cf 33 d2 f7 74 24 ?? 8a 04 0a 30 04 33 43 a1 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 2b c6 3b d8 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}