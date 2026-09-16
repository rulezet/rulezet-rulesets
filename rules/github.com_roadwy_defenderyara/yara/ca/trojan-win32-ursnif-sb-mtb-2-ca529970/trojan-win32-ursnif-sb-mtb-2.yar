rule Trojan_Win32_Ursnif_SB_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 44 24 14 8b c6 0f af 44 24 0c 83 64 24 24 00 69 c0 e3 48 00 00 0f b7 c0 57 0f b7 f8 6a 00 89 44 24 14 6a 02 } 		$a_01_1 = {66 83 c0 08 69 f6 84 04 00 00 0f b7 e8 0f b7 c5 03 f0 6b c0 4b 03 c3 89 6c 24 0c 03 e8 8b c5 69 c0 63 3b } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}