rule Trojan_Win64_Vidar_KK_MTB_5{
	meta:
		description = "Trojan:Win64/Vidar.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 4c 3c 50 89 ca c1 ea 04 0f b6 14 02 42 88 14 7e 83 e1 0f 0f b6 0c 01 42 88 4c 7e 01 42 0f b6 4c 3c 51 89 ca c1 ea 04 0f b6 14 02 42 88 54 7e 02 83 e1 0f 0f b6 0c 01 42 88 4c 7e 03 49 83 c7 02 4c 39 ff 75 b8 } 		$a_01_1 = {61 33 62 36 34 66 37 63 61 31 65 66 36 35 38 38 36 30 37 65 61 63 34 61 64 64 39 37 66 64 35 64 66 62 62 39 36 33 39 31 37 35 64 34 30 31 32 30 33 38 66 63 35 30 39 38 34 63 30 33 35 62 63 64 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5) >=25
 
}