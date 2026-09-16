rule Trojan_Win32_Redline_MRE_MTB{
	meta:
		description = "Trojan:Win32/Redline.MRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 24 0f b6 c0 2b cf 83 e1 f8 8a 44 04 48 30 86 ?? ?? ?? ?? 8b c7 81 f9 ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}