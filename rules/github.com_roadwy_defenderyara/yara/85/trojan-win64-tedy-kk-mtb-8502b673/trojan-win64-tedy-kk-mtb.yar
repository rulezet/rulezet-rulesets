rule Trojan_Win64_Tedy_KK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 32 f8 4d 8d 00 57 48 89 ff 48 8d 3f 5f 48 83 c2 01 4c 39 c2 75 e9 } 		$a_01_1 = {80 32 fc 4d 89 c9 48 89 ff 4d 89 c9 48 83 c2 01 4c 39 c2 75 eb } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}