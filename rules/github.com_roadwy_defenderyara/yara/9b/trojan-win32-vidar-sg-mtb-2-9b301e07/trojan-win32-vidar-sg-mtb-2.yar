rule Trojan_Win32_Vidar_SG_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 02 32 04 39 88 07 ff d6 68 ?? ?? ?? ?? ff d6 68 ?? ?? ?? ?? ff d6 8b 7d ?? 43 3b 5d ?? 72 a2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}