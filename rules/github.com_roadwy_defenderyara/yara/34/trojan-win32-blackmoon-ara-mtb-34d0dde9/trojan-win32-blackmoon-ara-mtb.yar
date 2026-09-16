rule Trojan_Win32_Blackmoon_ARA_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02 8a 17 88 10 40 47 4e 75 f7 } 		$a_00_1 = {63 6f 64 65 72 70 75 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}