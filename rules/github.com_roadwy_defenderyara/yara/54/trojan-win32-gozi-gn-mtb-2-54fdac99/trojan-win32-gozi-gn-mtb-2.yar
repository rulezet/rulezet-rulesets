rule Trojan_Win32_Gozi_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 10 33 f6 56 88 95 ?? ?? ?? ?? 53 45 e8 } 		$a_02_1 = {0f b6 d3 8d 54 02 ?? 8a c1 b1 ?? f6 e9 f6 db 2a d8 66 0f b6 44 24 ?? 66 0f af c5 66 2b c7 0f b7 c8 8b 06 05 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 02 d1 89 06 80 ea ?? 83 c6 ?? 83 6c 24 ?? 01 a3 ?? ?? ?? ?? 88 54 24 ?? 75 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}