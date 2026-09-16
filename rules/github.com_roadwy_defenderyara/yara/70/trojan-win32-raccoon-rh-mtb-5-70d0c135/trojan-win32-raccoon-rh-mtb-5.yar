rule Trojan_Win32_Raccoon_RH_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 [0-10] 89 45 ?? 8b 45 ?? 01 45 ?? 03 f3 33 75 ?? 33 75 } 		$a_01_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}