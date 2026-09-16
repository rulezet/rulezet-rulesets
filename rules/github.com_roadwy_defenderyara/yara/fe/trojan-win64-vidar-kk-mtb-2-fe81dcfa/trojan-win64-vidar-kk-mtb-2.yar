rule Trojan_Win64_Vidar_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 84 24 90 00 00 00 48 83 c0 14 4c 8b 94 24 a8 00 00 00 44 8b 8c 24 8c 00 00 00 4c 89 c2 4d 89 d0 66 90 } 		$a_01_1 = {48 8d 3c 03 4c 8d 04 33 45 0f b6 00 44 88 07 48 ff c3 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}