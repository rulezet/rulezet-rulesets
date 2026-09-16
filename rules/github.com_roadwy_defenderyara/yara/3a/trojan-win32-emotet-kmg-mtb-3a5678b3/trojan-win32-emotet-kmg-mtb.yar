rule Trojan_Win32_Emotet_KMG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 27 16 00 00 99 f7 fe 33 c0 8a ?? ?? ?? 41 81 f9 27 16 00 00 8b f2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}