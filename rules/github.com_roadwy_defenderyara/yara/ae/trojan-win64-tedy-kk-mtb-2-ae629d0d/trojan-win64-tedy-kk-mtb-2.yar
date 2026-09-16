rule Trojan_Win64_Tedy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b9 00 09 6e 88 f1 ff ff ff 48 8d 34 19 48 8d 76 ec 48 8b 7c 24 50 48 39 37 7d 93 } 		$a_01_1 = {48 8b 94 24 20 07 00 00 48 81 c2 38 02 00 00 4c 8b 84 24 d0 04 00 00 49 ff c8 48 8b 84 24 10 07 00 00 48 89 cb 48 8b b4 24 18 07 00 00 4c 89 c1 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}