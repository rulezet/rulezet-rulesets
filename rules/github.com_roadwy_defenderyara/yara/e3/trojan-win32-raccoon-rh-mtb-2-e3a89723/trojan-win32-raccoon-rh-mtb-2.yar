rule Trojan_Win32_Raccoon_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } 		$a_03_1 = {d3 e8 89 45 f4 8b 45 d4 01 45 f4 8b 45 f4 33 45 e8 89 35 ?? ?? ?? ?? 31 45 fc 2b 5d fc } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}