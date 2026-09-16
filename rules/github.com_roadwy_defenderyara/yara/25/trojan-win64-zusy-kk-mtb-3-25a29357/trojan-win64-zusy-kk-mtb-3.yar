rule Trojan_Win64_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 84 c0 } 		$a_01_1 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 66 0f be d0 8b 85 9c 01 00 00 48 98 66 89 94 45 e0 00 00 00 83 85 9c 01 00 00 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}