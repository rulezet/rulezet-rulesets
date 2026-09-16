rule Trojan_Win32_Raccoon_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c3 f7 f1 8b 45 fc 8a 0c 02 8d 14 33 8a 04 17 32 c1 43 88 02 } 		$a_03_1 = {8b 45 fc f7 f1 8a 0e 8b 45 fc 32 8a ?? ?? ?? ?? 40 88 0c 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}