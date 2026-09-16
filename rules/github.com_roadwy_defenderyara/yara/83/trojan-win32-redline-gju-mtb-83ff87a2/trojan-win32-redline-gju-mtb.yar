rule Trojan_Win32_Redline_GJU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 47 e2 } 		$a_03_1 = {d1 f9 0f b6 95 ?? ?? ?? ?? c1 e2 07 0b ca 88 8d ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d0 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}