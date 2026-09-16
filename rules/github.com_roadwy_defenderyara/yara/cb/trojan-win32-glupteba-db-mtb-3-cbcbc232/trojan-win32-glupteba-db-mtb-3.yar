rule Trojan_Win32_Glupteba_DB_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8a 44 02 ff 88 43 ff 3b 4d f4 77 df } 		$a_01_1 = {8b 55 a0 8b 45 9c 8b 00 89 02 8b 55 a0 8b 45 9c 8b 40 04 89 42 04 83 45 a0 08 83 45 9c 08 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}