rule Trojan_Win64_BazarLoader_QE_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QE!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 0a 88 44 0d 87 48 ff c1 48 83 f9 0d 72 ec } 		$a_01_1 = {0f b6 44 15 b7 8d 4a 4f 32 c8 88 4c 15 b7 48 ff c2 48 83 fa 0c 72 e9 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}