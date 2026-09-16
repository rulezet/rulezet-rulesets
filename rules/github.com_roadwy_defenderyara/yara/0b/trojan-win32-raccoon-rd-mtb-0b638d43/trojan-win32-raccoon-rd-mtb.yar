rule Trojan_Win32_Raccoon_RD_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3 } 		$a_01_1 = {8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}