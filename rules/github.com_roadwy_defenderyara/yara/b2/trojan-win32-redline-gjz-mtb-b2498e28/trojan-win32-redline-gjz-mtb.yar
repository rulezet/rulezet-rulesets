rule Trojan_Win32_Redline_GJZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 47 e2 } 		$a_03_1 = {f7 d2 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d8 88 85 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}