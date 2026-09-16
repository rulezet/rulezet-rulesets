rule Trojan_Win64_Tedy_AHE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f7 4d 1e 51 17 c7 45 fb 06 16 55 05 c7 45 ff 4c 45 47 16 c7 45 03 42 5a 13 54 c6 45 07 6c 0f 57 c0 } 		$a_01_1 = {48 8d 4d 27 49 83 fa 0f 49 0f 47 c9 33 d2 48 8b c3 49 f7 f3 44 32 04 0a 48 8b c7 48 83 7f 18 0f 76 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}