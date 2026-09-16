rule Trojan_Win32_Gozi_GE_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e8 be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 8d 71 ?? 03 55 ?? 8b ce 03 55 ?? d3 ea 52 8b 55 ?? 8d 0c 02 e8 } 		$a_02_1 = {8b 04 0a 85 c0 8b f8 75 ?? 33 db 43 eb ?? 2b 74 24 ?? 03 c6 89 01 8b f7 83 c1 04 4b 75 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}