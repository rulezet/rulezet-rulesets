rule Trojan_Win32_Redline_GJW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 80 2f ?? 47 e2 } 		$a_03_1 = {d1 fa 0f b6 85 ?? ?? ?? ?? c1 e0 ?? 0b d0 88 95 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}