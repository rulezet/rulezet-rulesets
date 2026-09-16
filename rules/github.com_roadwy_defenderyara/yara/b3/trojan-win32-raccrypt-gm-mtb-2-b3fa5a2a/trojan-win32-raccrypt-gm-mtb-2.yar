rule Trojan_Win32_Raccrypt_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 03 d0 c1 ?? 04 03 45 ?? c1 ?? 05 03 4d ?? 52 89 3d [0-04] 90 18 33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}