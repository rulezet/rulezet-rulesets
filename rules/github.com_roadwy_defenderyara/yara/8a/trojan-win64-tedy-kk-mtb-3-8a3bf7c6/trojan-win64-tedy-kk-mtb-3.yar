rule Trojan_Win64_Tedy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 88 45 f7 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 88 45 f6 0f b6 45 f7 0a 45 f6 } 		$a_01_1 = {89 c2 0f b6 45 f7 22 45 f6 f7 d0 21 d0 88 45 f5 8b 45 f8 48 63 d0 48 8b 45 10 48 01 c2 0f b6 45 f5 88 02 83 45 fc 01 83 45 f8 01 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}