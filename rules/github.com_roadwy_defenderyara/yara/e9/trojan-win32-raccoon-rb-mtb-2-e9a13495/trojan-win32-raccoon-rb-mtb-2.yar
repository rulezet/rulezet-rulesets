rule Trojan_Win32_Raccoon_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 90 33 d2 f7 f1 8b 45 88 8b 4d 80 57 8a 04 02 32 04 19 88 03 8d 45 94 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}