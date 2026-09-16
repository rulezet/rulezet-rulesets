rule Trojan_Win32_Raccoon_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}