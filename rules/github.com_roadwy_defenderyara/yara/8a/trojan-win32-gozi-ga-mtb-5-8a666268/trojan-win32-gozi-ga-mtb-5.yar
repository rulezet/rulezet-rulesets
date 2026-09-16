rule Trojan_Win32_Gozi_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c6 8d 7f 01 03 c1 a3 ?? ?? ?? ?? 8a 44 3b ff 88 47 ff 80 3d ?? ?? ?? ?? 08 8b 15 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 74 ?? c1 e1 ?? 2b ca eb } 		$a_02_1 = {83 c2 f8 0f b7 c0 01 55 ?? 99 85 d2 72 ?? 77 ?? 3b c6 90 18 8b 7d 08 ff 55 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}