rule Trojan_Win32_Radthief_AR_MTB{
	meta:
		description = "Trojan:Win32/Radthief.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 1e 33 d0 69 c2 ?? ?? ?? ?? 03 c1 89 44 8c 04 41 81 f9 } 		$a_01_1 = {8b 45 c8 8b 4d cc 89 45 c0 89 4d c4 ff d7 2b 45 d0 1b 55 d4 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}