rule Trojan_Win32_Raccoon_RA_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 e4 8d 44 24 08 c7 44 24 08 00 00 00 00 50 6a 40 68 7e 07 00 00 68 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}