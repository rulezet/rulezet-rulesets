rule Trojan_Win64_IcedID_D_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 48 ff 0f af c8 f6 c1 01 0f 94 c1 83 3d ?? ?? ?? ?? 0a 0f 9c c0 08 c8 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 71 ff 89 f7 0f af f9 84 c0 75 48 83 e7 01 e9 96 } 		$a_00_1 = {48 c1 ed 20 01 e9 89 cd c1 ed 1f c1 f9 06 01 e9 89 cd c1 e5 07 01 d5 29 e9 89 ca 81 c2 f7 0f 00 00 48 63 d2 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}