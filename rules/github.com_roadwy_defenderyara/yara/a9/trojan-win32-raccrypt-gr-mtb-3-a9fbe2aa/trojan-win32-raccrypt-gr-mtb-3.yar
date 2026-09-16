rule Trojan_Win32_Raccrypt_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 02 88 01 8b e5 5d c2 } 		$a_02_1 = {d3 ea 89 55 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-04] 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 50 8d 4d ?? 51 e8 [0-04] 8b 55 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}