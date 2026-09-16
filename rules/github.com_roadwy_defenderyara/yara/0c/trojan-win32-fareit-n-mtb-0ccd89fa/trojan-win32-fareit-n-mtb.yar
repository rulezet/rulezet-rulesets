rule Trojan_Win32_Fareit_N_MTB{
	meta:
		description = "Trojan:Win32/Fareit.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {d9 d0 8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 88 c8 59 29 f3 83 c3 01 75 02 89 fb 89 04 0a 83 c1 01 75 d8 } 		$a_01_1 = {81 ec 00 02 00 00 55 89 e5 e8 00 00 00 00 58 83 e8 0e 89 45 44 e8 9e 27 00 00 85 c9 e9 b5 19 00 00 59 89 4d 18 39 c9 b8 39 05 00 00 ba 6d 07 af 60 e8 a9 22 00 00 89 85 98 00 00 00 e9 b1 19 00 00 fc 59 ba c5 dc cf 94 e8 92 22 00 00 eb 1c 85 ff 5b 31 d2 52 54 53 85 db ff d0 58 83 f8 0c 7d 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}