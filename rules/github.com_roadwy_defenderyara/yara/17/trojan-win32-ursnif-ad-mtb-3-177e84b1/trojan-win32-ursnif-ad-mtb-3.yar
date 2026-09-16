rule Trojan_Win32_Ursnif_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 c2 20 c1 c1 07 0f be c2 33 c8 f7 d1 41 46 47 8a 16 84 d2 } 		$a_01_1 = {80 84 1d 1e ff ff ff f6 43 83 fb 0a 72 f2 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}