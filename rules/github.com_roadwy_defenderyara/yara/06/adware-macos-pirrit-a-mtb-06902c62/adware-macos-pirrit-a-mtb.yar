rule Adware_MacOS_Pirrit_A_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {66 ef 97 ac 2a 79 ba 21 b2 43 64 5f 68 67 63 74 9f 88 bc c0 2f 35 9b b4 2b 42 98 e2 0e c8 a1 ba 13 85 da } 		$a_00_1 = {20 52 5a 38 4c 55 f9 93 a1 04 61 f9 3a 3e 8e e8 3c ba 33 6d 8d 85 85 ca a9 0c 40 72 c0 de 66 32 26 2a a6 54 29 af 46 ac 86 07 80 47 97 b5 fb b1 42 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}