rule Trojan_Win64_Vidar_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 34 03 48 8b bc 24 98 00 00 00 48 01 df 0f b6 3f 40 88 3e 48 ff c3 } 		$a_03_1 = {48 8b 54 24 ?? 44 0f b6 4c 24 47 49 89 d8 48 89 cb 48 89 c1 48 8b 84 24 90 90 00 00 00 } 		$a_01_2 = {49 8d 40 01 48 8b b4 24 30 01 00 00 48 8b 8c 24 38 02 00 00 48 89 f2 48 8b bc 24 40 02 00 00 } 	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*15+(#a_01_2  & 1)*10) >=45
 
}