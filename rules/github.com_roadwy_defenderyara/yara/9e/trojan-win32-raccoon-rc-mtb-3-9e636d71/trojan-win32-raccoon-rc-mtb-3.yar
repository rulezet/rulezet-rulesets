rule Trojan_Win32_Raccoon_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {cc cc 81 01 e1 34 ef c6 c3 cc cc } 		$a_03_1 = {89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 [0-10] 33 c1 2b f0 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}