rule Trojan_Win64_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 44 0f b6 00 48 8b 45 28 0f b6 08 48 8b 55 18 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}