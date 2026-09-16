rule Trojan_Win64_Tedy_GHT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 24 21 32 80 74 24 22 33 80 74 24 23 34 80 74 24 24 35 80 74 24 25 36 80 74 24 26 37 80 74 24 27 38 66 89 4c 24 28 80 f1 39 80 74 24 29 3a 34 3b c6 44 24 20 42 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}