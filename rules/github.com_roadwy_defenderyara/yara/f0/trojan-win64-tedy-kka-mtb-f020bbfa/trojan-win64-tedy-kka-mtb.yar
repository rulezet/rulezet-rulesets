rule Trojan_Win64_Tedy_KKA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 20 8b 54 24 20 69 d2 ?? ?? ?? ?? 44 8b 44 24 20 ff 44 24 20 81 c2 ?? ?? ?? ?? 31 d1 8b 54 24 20 85 d2 } 		$a_01_1 = {52 45 4d 55 53 20 4c 4f 47 } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}