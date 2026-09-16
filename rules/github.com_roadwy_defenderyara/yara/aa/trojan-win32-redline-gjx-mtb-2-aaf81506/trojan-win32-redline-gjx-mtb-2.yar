rule Trojan_Win32_Redline_GJX_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 07 67 47 e2 } 		$a_03_1 = {f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 33 95 ?? ?? ?? ?? 88 95 ?? ?? ?? ?? 8b 85 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}