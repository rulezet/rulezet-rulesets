rule Trojan_Win32_Zusy_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 89 c2 c1 ea 1f 01 d0 d1 f8 89 c2 8b 45 08 01 d0 8b 4d f4 8b 55 f0 01 ca 0f b6 00 88 02 8b 45 f4 89 c2 c1 ea 1f 01 d0 d1 f8 89 c2 8b 45 08 01 d0 8b 55 f4 8d 4a 01 8b 55 f0 01 ca 0f b6 00 88 02 83 45 f4 01 } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}