rule Trojan_Win32_Raccoon_RB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 54 24 04 b8 3b 2d 0b 00 01 44 24 04 8b 44 24 04 8a 04 30 88 04 0e 46 3b 35 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}