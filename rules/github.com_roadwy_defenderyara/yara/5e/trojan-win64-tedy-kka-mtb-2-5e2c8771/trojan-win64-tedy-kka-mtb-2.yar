rule Trojan_Win64_Tedy_KKA_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 03 66 0f ef 00 48 83 c3 10 48 83 c0 10 0f 11 43 f0 4c 39 fb } 		$a_01_1 = {41 0f b6 54 05 00 41 30 14 06 48 83 c0 01 48 3b 84 24 d8 00 00 00 } 		$a_01_2 = {b9 20 00 00 00 89 d8 f3 aa b9 0c 00 00 00 48 8b 7c 24 30 f3 aa b9 20 00 00 00 48 89 ef f3 aa b9 0c 00 00 00 48 8b 7c 24 28 f3 aa b9 20 00 00 00 4c 89 e7 f3 aa b9 0c 00 00 00 48 8d 7c 24 60 f3 aa } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*7) >=25
 
}