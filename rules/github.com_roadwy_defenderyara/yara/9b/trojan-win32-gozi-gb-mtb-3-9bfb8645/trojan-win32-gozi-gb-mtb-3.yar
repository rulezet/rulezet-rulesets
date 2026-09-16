rule Trojan_Win32_Gozi_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 33 ff 4d 2b c5 1b d7 8b 7c 24 ?? 2b c1 1b d6 8b c8 8b f2 8b c7 05 [0-04] 8a 10 8b 44 24 ?? 88 97 [0-04] 8b d1 2b d0 83 ea 04 0f b7 d2 47 } 		$a_02_1 = {2a cb 89 37 80 e9 ?? 83 c7 04 83 6c 24 ?? 01 89 35 ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}