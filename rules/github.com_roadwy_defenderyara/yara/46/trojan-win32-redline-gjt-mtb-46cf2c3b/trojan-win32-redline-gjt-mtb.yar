rule Trojan_Win32_Redline_GJT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 47 e2 } 		$a_03_1 = {d1 f8 0f b6 8d ?? ?? ?? ?? c1 e1 07 0b c1 88 85 ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}