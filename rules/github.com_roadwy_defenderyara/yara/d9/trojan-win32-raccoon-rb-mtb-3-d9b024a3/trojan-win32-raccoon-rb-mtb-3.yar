rule Trojan_Win32_Raccoon_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 } 		$a_03_1 = {8b c6 c1 e0 04 03 45 ?? 33 45 ?? 33 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}