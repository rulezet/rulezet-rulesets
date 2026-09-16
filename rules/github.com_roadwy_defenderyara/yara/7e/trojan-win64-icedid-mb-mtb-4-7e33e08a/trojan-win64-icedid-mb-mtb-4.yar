rule Trojan_Win64_IcedID_MB_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 48 89 74 70 b7 45 89 44 24 18 55 03 e6 57 48 8b ec 48 83 b8 c7 49 8b f9 4d 8b f1 ed b8 1f 5a } 		$a_01_1 = {30 48 3b f9 26 ac 8a 42 40 48 03 c1 1c 9c f9 72 05 48 8b 12 bf 79 49 85 c9 0f 84 f4 54 a7 01 4c } 		$a_01_2 = {8b c0 4c 63 86 ef 98 83 e2 03 48 03 96 24 e1 03 48 2b c2 48 37 6f 40 0f b6 04 1a 44 5b 11 45 0d } 		$a_81_3 = {69 6e 69 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_81_3  & 1)*1) >=10
 
}