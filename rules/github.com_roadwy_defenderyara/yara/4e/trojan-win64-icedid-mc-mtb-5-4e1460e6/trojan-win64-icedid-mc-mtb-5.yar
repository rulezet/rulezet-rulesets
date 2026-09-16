rule Trojan_Win64_IcedID_MC_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 } 		$a_01_1 = {48 8b 40 60 48 8b 40 20 48 8d 54 24 60 e9 3d 02 00 00 } 		$a_01_2 = {48 8b 4c 24 48 0f b6 44 01 10 8b 4c 24 78 66 3b db 74 50 } 		$a_01_3 = {33 c8 8b c1 48 63 4c 24 44 e9 a4 00 00 00 } 		$a_01_4 = {48 8b 54 24 58 88 04 0a e9 dc fd ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=15
 
}