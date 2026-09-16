rule Trojan_Win64_IcedID_ME_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 54 24 20 88 04 0a eb 11 e9 7a ff ff ff 89 04 24 8b 44 24 28 e9 63 ff ff ff 8b 04 24 ff c0 eb ed eb 60 48 ff c0 48 89 04 24 3a c0 74 2e 88 08 48 8b 04 24 3a ff 74 eb 48 89 44 24 08 48 8b 44 24 30 eb 4e } 		$a_01_1 = {48 8b 44 24 20 48 89 04 24 3a d2 74 da 48 ff c8 48 89 44 24 30 eb 31 eb 3d 48 ff c0 48 89 04 24 66 3b d2 74 ce 4c 89 44 24 18 48 89 54 24 10 3a c9 74 9a 88 08 48 8b 04 24 3a c9 74 dc } 		$a_01_2 = {79 67 73 66 61 62 61 79 75 73 66 6a 6e 61 73 66 6b 61 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20) >=30
 
}